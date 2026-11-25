"""Scam Campaign DNA — groups radar findings into likely campaigns and explains every link.

Each finding is reduced to observable "genes":
  target brand · naming template · registered domain · page-path signature · TLD · lure words · time

Links (each with a plain-language reason and a strength):
  strong   – same registered domain (not a shared hosting platform)
  strong   – same brand + same naming template, e.g. "{brand}-secure-update"
  moderate – same distinctive page path on different sites (a reused phishing kit is likely)
  weak     – same brand, same domain ending and same lure word / trick within 72 hours

Campaigns are connected groups of 2+ findings. Shared traits suggest a common operator or kit;
they never prove it, and the output says so. Nothing here contacts the domains.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from ai.behavioral_analysis.url_analyzer import _LEET, _skeleton, brand_data
from ai.risk_assessment.intervention import ACTIONS

WINDOW = timedelta(hours=72)
GENERIC_PATHS = {"", "/", "/index.html", "/index.php", "/login", "/home", "/wp-admin", "/en", "/ar"}

SECTOR = {
    "banking": {"emiratesnbd", "adcb", "fab", "mashreq", "rakbank", "alrajhi", "paypal", "binance", "stc", "tabby", "tamara"},
    "government": {"uaepass", "dubaipolice", "salik", "dewa"},
    "delivery": {"dhl", "aramex", "fedex", "emiratespost"},
    "social": {"facebook", "instagram", "whatsapp", "google", "microsoft", "apple", "netflix", "roblox", "steam"},
}
HARM = {
    "banking": ("Theft of online-banking logins, card details and one-time codes", "سرقة بيانات الدخول المصرفي وبيانات البطاقات ورموز التحقق",
                ["open_link", "share_credentials"]),
    "government": ("Fake fines or government-service pages that steal UAE PASS / ID details and card payments",
                   "صفحات مخالفات أو خدمات حكومية مزيّفة تسرق بيانات الهوية الرقمية والبطاقات", ["open_link", "share_personal_data"]),
    "delivery": ("Fake parcel or customs fees that collect card details", "رسوم شحن أو جمارك وهمية لجمع بيانات البطاقات",
                 ["open_link", "transfer_money"]),
    "social": ("Account takeover through fake login pages", "الاستيلاء على الحسابات عبر صفحات دخول مزيّفة", ["open_link", "share_credentials"]),
    "jobs": ("Fake job offers that ask for fees or personal documents", "عروض عمل وهمية تطلب رسوماً أو وثائق شخصية",
             ["share_personal_data", "transfer_money"]),
    "unknown": ("Phishing pages that collect credentials or payments", "صفحات تصيّد تجمع بيانات الدخول أو المدفوعات", ["open_link", "share_credentials"]),
}


# How each kind of campaign usually reaches and harms people: the next harmful step to expect and the
# engine tactics behind it (so prevention links straight to "how this scam works" in Family Shield).
SCRIPT = {
    "banking": ("A message says your account or card is blocked and links to a page like these. It asks for your login, then for the one-time code your bank sends.",
                "رسالة تقول إن حسابك أو بطاقتك موقوفة وتوجّهك لصفحة مثل هذه، تطلب بيانات الدخول ثم رمز التحقق الذي يرسله البنك.",
                ["authority_impersonation", "urgency", "link_prompt", "credential_request"]),
    "government": ("A fake fine or service notice links here. The page asks for your UAE PASS login, Emirates ID and a card payment.",
                   "إشعار مخالفة أو خدمة مزيّف يوجّهك إلى هنا، والصفحة تطلب دخول الهوية الرقمية ورقم الهوية ودفعاً بالبطاقة.",
                   ["authority_impersonation", "threat_fear", "link_prompt", "personal_data_request", "payment_instruction"]),
    "delivery": ("An SMS about a held parcel links here and asks for a small fee by card — more charges follow.",
                 "رسالة عن شحنة محتجزة توجّهك إلى هنا وتطلب رسوماً بسيطة بالبطاقة، ثم تتبعها خصومات أكبر.",
                 ["identity_claim", "urgency", "link_prompt", "payment_instruction"]),
    "social": ("A 'security alert' or 'verify your account' message links here. The page captures your password and login code to take over the account.",
               "رسالة «تنبيه أمني» أو «وثّق حسابك» توجّهك إلى هنا، والصفحة تسرق كلمة المرور ورمز الدخول للاستيلاء على الحساب.",
               ["authority_impersonation", "threat_fear", "link_prompt", "credential_request"]),
    "jobs": ("A job offer leads here, then asks for a registration fee or copies of your passport and Emirates ID.",
             "عرض عمل يقودك إلى هنا ثم يطلب رسوم تسجيل أو نسخاً من جوازك وهويتك.",
             ["job_task_scam", "reward_lure", "personal_data_request", "payment_instruction"]),
    "unknown": ("A link in a message or post leads here. The page asks you to sign in or to pay.",
                "رابط في رسالة أو منشور يقودك إلى هنا، والصفحة تطلب تسجيل الدخول أو الدفع.",
                ["link_prompt", "credential_request", "payment_instruction"]),
}


def _parse_time(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.min


def _brand_tokens(brand: str | None) -> set[str]:
    if not brand:
        return set()
    v = brand_data()["brands"].get(brand, {})
    return {n.replace(" ", "").lower() for n in v.get("names", []) if n.isascii()} | {brand}


def genes(item: dict) -> dict:
    host = item["host"]
    reg = item.get("registrable_domain") or host
    data = brand_data()
    shared = reg in data.get("shared_hosting", [])
    label = _skeleton(reg).split(".")[0]
    toks = [t for t in re.split(r"[-_]", label) if t]
    btoks = _brand_tokens(item.get("brand"))
    template = None
    if item.get("brand") and not shared:
        norm = ["{brand}" if (t in btoks or t.translate(_LEET) in btoks) else re.sub(r"\d+", "#", t) for t in toks]
        if "{brand}" in norm and len(norm) > 1:
            template = "-".join(norm)
    path = ""
    if item.get("url"):
        p = urlsplit(item["url"]).path.lower().rstrip("/")
        p = re.sub(r"/[0-9a-f]{6,}|/\d+", "/#", p)
        segs = [s for s in p.split("/") if s][:2]
        path = "/" + "/".join(segs) if segs else ""
    stem = None
    if shared and host.endswith("." + reg):
        first = host[: -len(reg) - 1].split(".")[-1]
        kept = [t for t in first.split("-") if t and not re.search(r"\d", t)]
        if len(kept) >= 2 and len("-".join(kept)) >= 8:
            stem = "-".join(kept)
    lures = set(data.get("radar_lure_words", []))
    all_toks = set(toks) | set(re.split(r"[.\-_]", host))
    return {
        "brand": item.get("brand"),
        "reg": None if shared else reg,
        "shared_platform": reg if shared else None,
        "template": template,
        "stem": stem,
        "path": path if path not in GENERIC_PATHS and len(path) >= 6 else None,
        "tld": host.rsplit(".", 1)[-1],
        # the CT entry the name was found in: two names on one certificate were requested together
        "cert": (f"{ev['log']}#{ev['entry_index']}" if isinstance(ev := item.get("evidence") or {}, dict)
                 and ev.get("log") and ev.get("entry_index") is not None else None),
        "lures": sorted(w for w in lures if w in all_toks),
        "method": item.get("method"),
        "time": _parse_time(item.get("first_seen", "")),
    }


def _sector(brand: str | None, lures: list[str]) -> str:
    if any(l in ("careers", "jobs", "job", "recruitment", "hiring") for l in lures):
        return "jobs"
    for s, brands in SECTOR.items():
        if brand in brands:
            return s
    return "unknown"


def build_campaigns(items: list[dict]) -> list[dict]:
    """items: radar rows (id, host, registrable_domain, url, brand, method, first_seen, last_seen, confirmed)."""
    return analyze_relationships(items)[0]


def analyze_relationships(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Campaigns plus *every* explainable link between findings (used by the Threat Constellation)."""
    g = {it["id"]: genes(it) for it in items}
    by_id = {it["id"]: it for it in items}
    parent = {i: i for i in by_id}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    edges: list[dict] = []

    def site(i):
        h = by_id[i]["host"]
        return h[4:] if h.startswith("www.") else h

    def link(a, b, key, strength, en, ar):
        if a == b or site(a) == site(b):
            return  # "www.x" and "x" are the same site, not a campaign
        edges.append({"a": a, "b": b, "key": key, "strength": strength, "en": en, "ar": ar})
        parent[find(a)] = find(b)

    blocks: dict[tuple, list[int]] = defaultdict(list)
    for i, ge in g.items():
        if ge["reg"]:
            blocks[("reg", ge["reg"])].append(i)
        if ge["template"]:
            blocks[("tpl", ge["brand"], ge["template"])].append(i)
        if ge["path"]:
            blocks[("path", ge["path"])].append(i)
        if ge["stem"]:
            blocks[("stem", ge["shared_platform"], ge["stem"])].append(i)
        if ge["cert"]:
            blocks[("cert", ge["cert"])].append(i)
    for key, ids in blocks.items():
        if len(ids) < 2:
            continue
        ids.sort(key=lambda x: g[x]["time"])
        anchor = ids[0]
        for other in ids[1:]:
            if key[0] == "cert":
                log, idx = key[1].rsplit("#", 1)
                link(anchor, other, key, "strong", f"Both names are on the same TLS certificate ({log}, entry {idx}) — they were requested together",
                     f"الاسمان في شهادة TLS واحدة ({log}، الإدخال {idx}) — طُلبا معاً")
            elif key[0] == "reg":
                link(anchor, other, key, "strong", f"Both are hosted under the same registered domain {key[1]}",
                     f"كلاهما مستضاف تحت النطاق المسجّل نفسه {key[1]}")
            elif key[0] == "tpl":
                if by_id[anchor]["registrable_domain"] == by_id[other]["registrable_domain"]:
                    continue
                link(anchor, other, key, "strong", f"Same naming pattern '{key[2]}' imitating {key[1]}",
                     f"نمط التسمية نفسه '{key[2]}' لتقليد {key[1]}")
            elif key[0] == "stem":
                link(anchor, other, key, "moderate", f"Same sub-domain naming '{key[2]}-…' on the free platform {key[1]}",
                     f"تسمية النطاق الفرعي نفسها '{key[2]}-…' على المنصة المجانية {key[1]}")
            elif key[0] == "path" and by_id[anchor]["host"] != by_id[other]["host"]:
                if abs(g[other]["time"] - g[anchor]["time"]) <= timedelta(days=7):
                    link(anchor, other, key, "moderate", f"Same page path '{key[1]}' on different sites — a reused phishing kit is likely",
                         f"مسار الصفحة نفسه '{key[1]}' على مواقع مختلفة — يُرجّح استخدام أداة تصيّد واحدة")
    # weak: same brand + TLD + trick/lure within 72h (sequential in time)
    weak: dict[tuple, list[int]] = defaultdict(list)
    for i, ge in g.items():
        if ge["brand"]:
            weak[(ge["brand"], ge["tld"], ge["method"])].append(i)
        elif ge["shared_platform"] and ge["lures"]:
            weak[(ge["shared_platform"], ge["tld"], "platform")].append(i)
    for (brand, tld, method), ids in weak.items():
        ids.sort(key=lambda x: g[x]["time"])
        for a, b in zip(ids, ids[1:]):
            ga, gb = g[a], g[b]
            shared_lure = set(ga["lures"]) & set(gb["lures"])
            if gb["time"] - ga["time"] <= WINDOW and (shared_lure or method == "subdomain") and find(a) != find(b):
                why = f"lure word '{sorted(shared_lure)[0]}'" if shared_lure else f"'{brand}' placed in a sub-domain"
                why_ar = f"كلمة الاستدراج '{sorted(shared_lure)[0]}'" if shared_lure else f"وضع '{brand}' في نطاق فرعي"
                if method == "platform":
                    link(a, b, ("weak", brand, tld), "weak", f"Same free platform {brand} and {why} within 72 hours",
                         f"المنصة المجانية نفسها {brand} و{why_ar} خلال 72 ساعة")
                else:
                    link(a, b, ("weak", brand, tld), "weak", f"Same target ({brand}), same ending .{tld} and {why} within 72 hours",
                         f"الهدف نفسه ({brand}) والامتداد نفسه ‎.{tld}‎ و{why_ar} خلال 72 ساعة")

    comps: dict[int, list[int]] = defaultdict(list)
    for i in by_id:
        comps[find(i)].append(i)
    campaigns = []
    for members in comps.values():
        if len({by_id[m]["host"].removeprefix("www.") for m in members}) < 2:
            continue
        mset = set(members)
        cedges = [e for e in edges if e["a"] in mset]
        key_counts = Counter(e["key"] for e in cedges)
        top_key = key_counts.most_common(1)[0][0]
        cid = "C-" + hashlib.sha1(repr(top_key).encode(), usedforsecurity=False).hexdigest()[:6].upper()
        brands = Counter(g[m]["brand"] for m in members if g[m]["brand"])
        brand = brands.most_common(1)[0][0] if brands else None
        lures = sorted({l for m in members for l in g[m]["lures"]})
        sector = _sector(brand, lures)
        harm_en, harm_ar, action_keys = HARM[sector]
        strengths = Counter(e["strength"] for e in cedges)
        confidence = "high" if strengths["weak"] == 0 and strengths["moderate"] == 0 else "medium" if strengths["strong"] or strengths["moderate"] else "low"
        confirmed = [m for m in members if by_id[m].get("confirmed")]
        times = sorted(g[m]["time"] for m in members)
        last_seen = max(_parse_time(by_id[m].get("last_seen") or by_id[m].get("first_seen", "")) for m in members)
        if top_key[0] == "tpl":
            shown = top_key[2].replace("{brand}", top_key[1]).replace("#", "N")
            name_en, name_ar = f"Fake {top_key[1]} sites named '{shown}.*'", f"مواقع مزيّفة لـ {top_key[1]} باسم '{shown}.*'"
        elif top_key[0] == "path":
            name_en, name_ar = f"Phishing kit at path '{top_key[1]}'", f"أداة تصيّد على المسار '{top_key[1]}'"
            if brand:
                name_en, name_ar = f"Fake {brand} pages — shared kit '{top_key[1]}'", f"صفحات {brand} مزيّفة — أداة مشتركة '{top_key[1]}'"
        elif top_key[0] == "stem":
            name_en, name_ar = f"'{top_key[2]}-…' sites on {top_key[1]}", f"مواقع '{top_key[2]}-…' على {top_key[1]}"
        elif top_key[0] == "weak" and top_key[1] in brand_data().get("shared_hosting", []):
            name_en, name_ar = f"Lure sites on {top_key[1]}", f"مواقع استدراج على {top_key[1]}"
        elif top_key[0] == "reg":
            name_en, name_ar = f"Phishing pages under {top_key[1]}", f"صفحات تصيّد تحت {top_key[1]}"
        elif top_key[0] == "cert":
            who = brand or "unknown target"
            name_en, name_ar = f"{who} look-alikes on one certificate", f"مواقع مقلّدة لـ {who} على شهادة واحدة"
        else:
            name_en, name_ar = f"Sites targeting {top_key[1]} (.{top_key[2]})", f"مواقع تستهدف {top_key[1]} (‎.{top_key[2]}‎)"
        official = brand_data()["brands"].get(brand, {}).get("domains", []) if brand else []
        gene_list = []
        if brand:
            gene_list.append({"key": "target", "value": brand, "count": brands[brand]})
        for k in ("template", "path", "tld", "shared_platform"):
            c = Counter(g[m][k] for m in members if g[m][k])
            if c:
                v, n = c.most_common(1)[0]
                if n >= 2:
                    gene_list.append({"key": k, "value": v, "count": n})
        lure_c = Counter(l for m in members for l in g[m]["lures"])
        if lure_c:
            gene_list.append({"key": "lures", "value": ", ".join(w for w, _ in lure_c.most_common(4)), "count": lure_c.most_common(1)[0][1]})
        campaigns.append({
            "id": cid, "name_en": name_en, "name_ar": name_ar, "brand": brand, "sector": sector,
            "members": sorted(members, key=lambda m: g[m]["time"]),
            "hosts": [by_id[m]["host"] for m in sorted(members, key=lambda m: g[m]["time"])],
            "confirmed_flags": [bool(by_id[m].get("confirmed")) for m in sorted(members, key=lambda m: g[m]["time"])],
            "size": len(members), "confirmed": len(confirmed), "suspected": len(members) - len(confirmed),
            "status": "confirmed" if confirmed else "suspected",
            "confidence": confidence, "first_seen": times[0].isoformat(), "last_seen": last_seen.isoformat(),
            "genes": gene_list,
            "links": [{k: e[k] for k in ("a", "b", "strength", "en", "ar")} for e in cedges][:40],
            "harm_en": harm_en, "harm_ar": harm_ar,
            "prevention": [{"en": ACTIONS[k]["en"], "ar": ACTIONS[k]["ar"]} for k in action_keys]
            + ([{"en": f"Type {official[0]} yourself instead of using links", "ar": f"اكتب {official[0]} بنفسك بدلاً من استخدام الروابط"}] if official else []),
            "uncertainty_en": "Shared traits suggest a common operator or phishing kit but do not prove it. Members marked 'suspected' are automated detections and may be legitimate.",
            "uncertainty_ar": "تشير السمات المشتركة إلى جهة أو أداة تصيّد واحدة لكنها لا تثبت ذلك. العناصر المصنّفة 'مشتبه بها' رصد آلي وقد تكون مشروعة.",
        })
    # IDs come from the campaign's main shared trait, so separate groups sharing a broad trait (e.g. "apple + .com")
    # would collide. Unique IDs are kept as they are (stable links); colliding ones get the group's earliest site mixed in.
    seen = Counter(c["id"] for c in campaigns)
    for c in campaigns:
        if seen[c["id"]] > 1:
            first = min((by_id[m]["first_seen"], by_id[m]["host"]) for m in c["members"])
            c["id"] = "C-" + hashlib.sha1(f"{c['id']}|{first[1]}".encode(), usedforsecurity=False).hexdigest()[:6].upper()
    if len({c["id"] for c in campaigns}) != len(campaigns):   # vanishingly rare: lengthen until unique
        used: set[str] = set()
        for c in campaigns:
            base, k = c["id"], 0
            while c["id"] in used:
                k += 1
                c["id"] = "C-" + hashlib.sha1(f"{base}|{k}".encode(), usedforsecurity=False).hexdigest()[:6].upper()
            used.add(c["id"])
    campaigns.sort(key=lambda c: (c["status"] != "confirmed", -c["size"], c["last_seen"]), reverse=False)
    member_of = {m: c["id"] for c in campaigns for m in c["members"]}
    all_edges = [{"a": e["a"], "b": e["b"], "strength": e["strength"], "en": e["en"], "ar": e["ar"],
                  "campaign_id": member_of.get(e["a"])} for e in edges]
    return campaigns, all_edges


def campaign_of(campaigns: list[dict]) -> dict[int, dict]:
    """item id -> campaign summary (for prevention/investigation lookups)."""
    out = {}
    for c in campaigns:
        for m in c["members"]:
            out[m] = {"campaign_id": c["id"], "name_en": c["name_en"], "name_ar": c["name_ar"], "size": c["size"],
                      "status": c["status"]}
    return out


def template_index(campaigns: list[dict], items_by_id: dict[int, dict]) -> dict[tuple, dict]:
    """(brand, naming template) -> campaign summary, for predicting not-yet-seen domains."""
    idx = {}
    for c in campaigns:
        for gn in c["genes"]:
            if gn["key"] == "template" and c["brand"]:
                idx[(c["brand"], gn["value"])] = {"campaign_id": c["id"], "name_en": c["name_en"], "name_ar": c["name_ar"],
                                                  "size": c["size"], "status": c["status"]}
    return idx
