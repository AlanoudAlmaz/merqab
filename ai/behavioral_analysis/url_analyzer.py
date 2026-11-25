"""Static, offline analysis of URLs.

MERQAB never fetches the analysed URL (doing so could alert the attacker, trigger downloads or
expose the server). Reputation services can be plugged in through ``ReputationProvider``.
"""
from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

_DATA = Path(__file__).resolve().parent.parent / "data" / "brands.json"

URL_RE = re.compile(
    r"((?:h[tx]{2}ps?|ftp)(?::|\[:\])//[^\s<>\"'()]+|www\.[^\s<>\"'()]+|"
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62})(?:\.|\[\.\]))+(?:[a-z]{2,24})(?:/[^\s<>\"'()]*)?)",
    re.IGNORECASE,
)
_COMMON_FILE_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx", "csv", "json", "html", "py", "js"}
DANGEROUS_EXT = (".apk", ".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1", ".dmg", ".iso", ".lnk", ".hta")
KEYWORDS = ("login", "signin", "sign-in", "verify", "verification", "secure", "update", "account", "wallet",
            "otp", "confirm", "kyc", "refund", "prize", "reward", "unlock", "suspend", "billing", "payment", "bank")


@lru_cache(maxsize=1)
def brand_data() -> dict:
    return json.loads(_DATA.read_text(encoding="utf-8"))


def refang(url: str) -> str:
    return (url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
            .replace("hxxps", "https").replace("hxxp", "http").replace("HXXP", "http"))


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 without a full public-suffix list (documented limitation)."""
    labels = [l for l in host.lower().strip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    sl = brand_data()["second_level_suffixes"]
    if len(labels[-1]) == 2 and labels[-2] in sl:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?…»)")
        if "." not in refang(raw):
            continue
        # skip things that are plainly file names ("report.pdf") or decimals
        bare = refang(raw).lower()
        if not bare.startswith(("http", "www", "ftp")):
            tail = bare.rsplit(".", 1)[-1].split("/")[0]
            if tail in _COMMON_FILE_EXT and "/" not in bare:
                continue
            if re.fullmatch(r"[\d.]+", bare):
                continue
        if raw not in found:
            found.append(raw)
    return found


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


_CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                             "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ⅼ": "l", "ı": "i", "ο": "o", "α": "a"})


def _skeleton(host: str) -> str:
    """Decode punycode and map common confusable letters to Latin for brand comparison."""
    try:
        decoded = host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, ValueError):
        decoded = host
    return decoded.translate(_CONFUSABLE)


def _scripts(s: str) -> set[str]:
    out = set()
    for ch in s:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


@dataclass
class UrlSignal:
    key: str
    weight: int
    en: str
    ar: str


@dataclass
class UrlReport:
    url: str
    defanged: str
    host: str
    registrable_domain: str
    scheme: str
    score: int = 0
    level: str = "low"
    signals: list[UrlSignal] = field(default_factory=list)
    impersonated_brand: str | None = None
    official_domain: bool = False
    reputation: dict = field(default_factory=lambda: {"status": "not_configured"})
    redirect_target: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url, "defanged": self.defanged, "host": self.host,
            "registrable_domain": self.registrable_domain, "scheme": self.scheme,
            "score": self.score, "level": self.level, "impersonated_brand": self.impersonated_brand,
            "official_domain": self.official_domain, "reputation": self.reputation, "redirect_target": self.redirect_target,
            "signals": [s.__dict__ for s in self.signals],
        }


def _level(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"


_REDIRECT_KEYS = ("url", "u", "q", "redirect", "redirect_uri", "redirect_url", "redir", "next", "target", "dest", "destination",
                  "link", "goto", "to", "continue", "return", "returnurl", "r", "out")


def _embedded_url(parts, depth: int) -> str | None:
    if depth >= 2:
        return None
    from urllib.parse import parse_qsl
    for k, v in parse_qsl(parts.query or "", keep_blank_values=False):
        v = unquote(unquote(v)).strip()
        if (k.lower() in _REDIRECT_KEYS or v.lower().startswith(("http://", "https://"))) and re.match(r"^(https?:)?//[^/\s]+\.[^/\s]+", v, re.I):
            return v if v.lower().startswith("http") else "https:" + v
    m = re.search(r"/(https?(:|%3a)(//|%2f%2f)[^\s]+)$", unquote(parts.path or ""), re.I)
    return unquote(m.group(1)) if m else None


def analyze_url(raw: str, _depth: int = 0) -> UrlReport:
    url = refang(raw.strip())
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url_for_parse = "http://" + url
        scheme = "none"
    else:
        url_for_parse = url
        scheme = url.split(":", 1)[0].lower()
    parts = urlsplit(url_for_parse)
    host = (parts.hostname or "").lower()
    reg = registrable_domain(host)
    rep = UrlReport(url=raw.strip(), defanged=defang(url), host=host, registrable_domain=reg, scheme=scheme)
    sig = rep.signals
    data = brand_data()

    def add(key, w, en, ar):
        sig.append(UrlSignal(key, w, en, ar))

    # official brand domain?
    official_domains = {d: b for b, v in data["brands"].items() for d in v["domains"]}
    if reg in official_domains:
        rep.official_domain = True
    else:
        label, _, suffix = reg.partition(".")
        cc = suffix.rsplit(".", 1)[-1]
        # only brands that really run country sites (their official list has a country-code domain)
        brand_labels = {d.split(".")[0] for d in official_domains
                        if any(len(x.rsplit(".", 1)[-1]) == 2 for x in data["brands"][official_domains[d]]["domains"])}
        if label in brand_labels and len(cc) == 2 and cc not in data["suspicious_tlds"] and (suffix == cc or suffix.split(".")[0] in ("co", "com", "ne", "or", "org", "net")):
            rep.official_domain = True     # a brand's own country site, e.g. google.de, amazon.co.jp

    if scheme == "http":
        add("no_tls", 8, "Not encrypted (http instead of https)", "غير مشفر (http بدلاً من https)")
    try:
        ipaddress.ip_address(host)
        add("ip_host", 25, "Uses a raw IP address instead of a domain name", "يستخدم عنوان IP مباشرة بدلاً من اسم نطاق")
    except ValueError:
        pass
    if "xn--" in host:
        add("punycode", 25, "Internationalised (punycode) domain that can imitate familiar letters",
            "نطاق مُرمّز (punycode) يمكن أن يقلد حروفاً مألوفة")
    try:
        decoded_host = host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, ValueError):
        decoded_host = host
    if len(_scripts(decoded_host)) > 1:
        add("mixed_script", 30, "Domain mixes alphabets (look-alike characters)", "النطاق يخلط بين أبجديات مختلفة (حروف متشابهة)")
    if reg in data["shorteners"]:
        add("shortener", 20, "Link shortener hides the real destination", "خدمة اختصار تخفي الوجهة الحقيقية")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in data["suspicious_tlds"] and not rep.official_domain:
        add("risky_tld", 8, f"Domain ending '.{tld}' is frequently abused (weak signal on its own)",
            f"امتداد النطاق ‎.{tld}‎ يُساء استخدامه كثيراً (مؤشر ضعيف بمفرده)")
    if "@" in (parts.netloc or ""):
        add("userinfo", 20, "Contains '@', which hides the real website address", "يحتوي على '@' الذي يخفي عنوان الموقع الحقيقي")
    if parts.port and parts.port not in (80, 443):
        add("odd_port", 10, f"Uses unusual port {parts.port}", f"يستخدم منفذاً غير معتاد {parts.port}")
    sub_labels = host[: -len(reg)].strip(".").split(".") if host.endswith(reg) and host != reg else []
    if len([s for s in sub_labels if s]) >= 3:
        add("deep_subdomains", 10, "Unusually many sub-domains", "عدد كبير غير معتاد من النطاقات الفرعية")
    shared = data.get("shared_hosting", [])
    on_free_host = host != reg and (reg in shared or any(host.endswith("." + d) for d in shared))
    if on_free_host and not rep.official_domain:
        add("free_hosting", 14, f"Hosted on a free site builder ({reg}) — anyone can publish there in minutes, so it says nothing about who runs it",
            f"مستضاف على منصة مواقع مجانية ({reg}) — يستطيع أي شخص النشر فيها خلال دقائق، فلا تدل على هوية صاحبه")
    first = sub_labels[0] if sub_labels else (reg.split(".")[0] if reg else "")
    digits = sum(c.isdigit() for c in first)
    vowels = sum(c in "aeiou" for c in first)
    looks_generated = len(first) >= 10 and (first.count("-") >= 3 or (digits >= 3 and len(first) >= 12)
                                            or (len(first) >= 12 and vowels / max(1, sum(c.isalpha() for c in first)) < 0.22))
    if looks_generated and not rep.official_domain:
        add("generated_name", 12 if on_free_host else 8, "The site name looks machine-generated (random letters, digits or many hyphens)",
            "اسم الموقع يبدو مولّداً آلياً (حروف أو أرقام عشوائية أو شرطات كثيرة)")
    path_q = unquote((parts.path or "") + "?" + (parts.query or "")).lower()
    if any(path_q.split("?")[0].endswith(ext) for ext in DANGEROUS_EXT) or host.endswith(".apk"):
        add("dangerous_download", 30, "Points to an app or program download", "يشير إلى تحميل تطبيق أو برنامج")
    full_l = (host + path_q)
    if any(k in full_l for k in KEYWORDS) and not rep.official_domain:
        add("lure_keywords", 8, "Uses login/verification/payment words", "يستخدم كلمات تسجيل دخول/تحقق/دفع")
    raw_q = (parts.query or "") + (parts.fragment or "")
    if re.search(r"(e-?mail|user|login)=[^&]*(@|%40)|[a-z0-9._%+-]+(@|%40|%2540)[a-z0-9-]+\.[a-z]{2,}", raw_q, re.I) and not rep.official_domain:
        add("email_prefilled", 12, "Your e-mail address is pre-filled in the link — typical of targeted phishing pages",
            "بريدك الإلكتروني مُدرج مسبقاً في الرابط — سمة شائعة لصفحات التصيّد الموجّهة")
    if not rep.official_domain and host:
        path_l = (parts.path or "").lower()
        for b, v in data["brands"].items():
            if any(n.isascii() and len(n) >= 5 and re.search(rf"(^|[/_.\-]){re.escape(n.replace(' ', ''))}([/_.\-]|$)", path_l) for n in v["names"] + [b]):
                add("brand_in_path", 15, f"Mentions '{b}' in the page address but is not a {b} website",
                    f"يذكر '{b}' في عنوان الصفحة لكنه ليس موقعاً تابعاً لـ {b}")
                break
    if len(url) > 120:
        add("long", 5, "Very long address", "عنوان طويل جداً")
    if url.count("%") >= 6 or url_for_parse.lower().startswith(("data:", "javascript:")):
        add("obfuscated", 12, "Heavily encoded or script link", "رابط مُرمّز بكثافة أو برمجي")

    # brand impersonation and typo-squatting
    if not rep.official_domain and host:
        skeleton = _skeleton(host)
        host_tokens = [t for t in re.split(r"[.\-_]", skeleton) if t]
        folded_tokens = [t.translate(_LEET) for t in host_tokens]
        for brand, v in data["brands"].items():
            names = [n.replace(" ", "") for n in v["names"] if n.isascii()]
            exact = any(tok == n or (len(n) >= 6 and n in tok) for tok in host_tokens for n in names + [brand])
            leet = not exact and any(tok == n for tok in folded_tokens for n in names + [brand])
            if exact or leet:
                rep.impersonated_brand = brand
                if leet or skeleton != host:
                    add("typosquat", 35, f"Domain imitates '{brand}' using look-alike characters",
                        f"النطاق يقلّد '{brand}' باستخدام حروف متشابهة")
                else:
                    add("brand_lookalike", 35,
                        f"Uses the name '{brand}' but is not an official {brand} domain",
                        f"يستخدم اسم '{brand}' لكنه ليس نطاقاً رسمياً لـ {brand}")
                break
            for n in names:
                if len(n) >= 5 and any(len(tok) >= 5 and 0 < _levenshtein(tok, n) <= (1 if len(n) < 7 else 2) for tok in folded_tokens):
                    rep.impersonated_brand = brand
                    add("typosquat", 35, f"Domain is a misspelling of '{brand}'", f"النطاق تهجئة محرّفة لـ '{brand}'")
                    break
            if rep.impersonated_brand:
                break

    # Redirect / wrapper evasion: a trusted-looking link that forwards to another address
    # (google.com/url?q=…, l.facebook.com/l.php?u=…, ?redirect=https://…). MERQAB never opens links,
    # so it unwraps the embedded destination from the address itself and analyses that too.
    inner = _embedded_url(parts, _depth)
    if inner:
        sub = analyze_url(inner, _depth=_depth + 1)
        # the hop itself is a weak signal; it matters when the destination is suspicious in its own right
        add("redirect_wrapper", 12 if sub.score >= 20 else 4, f"Forwards to another address: {sub.defanged[:80]}",
            f"يعيد التوجيه إلى عنوان آخر: {sub.defanged[:80]}")
        rep.redirect_target = sub.defanged
        for x in sub.signals:
            if x.key not in {y.key for y in sig}:
                sig.append(UrlSignal(x.key, x.weight, "→ " + x.en, "← " + x.ar))
        if sub.impersonated_brand and not rep.impersonated_brand:
            rep.impersonated_brand = sub.impersonated_brand
        if rep.official_domain and sub.score >= 20:
            rep.official_domain = False      # a real brand domain used as a springboard to a risky destination

    rep.score = min(100, sum(s.weight for s in sig))
    if rep.official_domain and rep.score < 20:
        rep.score = 0
    rep.level = _level(rep.score)
    return rep


class ReputationProvider:
    """Integration point for URL reputation services (Safe Browsing, VirusTotal, national CERT feeds).

    The default implementation performs no lookup and says so explicitly.
    """

    name = "none"

    def lookup(self, url: str) -> dict:  # pragma: no cover - interface
        return {"status": "not_configured", "provider": self.name}
