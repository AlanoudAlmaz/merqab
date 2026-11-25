"""Evidence & takedown pack for a suspicious link.

Collects, without ever opening the suspicious website:
* registration data from RDAP (the IETF successor of WHOIS): registrar, registration / expiry dates, status,
  name servers and the registrar's abuse contact; a domain younger than 30 days is flagged as newly registered;
* hosting data: the IP addresses the name resolves to and the RDAP record of that network (owner, country, abuse);
* MERQAB's own explainable analysis and any live-radar / threat-feed record of the domain;
* UTC timestamps and a SHA-256 fingerprint so the pack can be cited and verified later.

Only rdap.org and the HTTPS RDAP servers it redirects to are contacted (fixed hosts; no SSRF). Every step reports
"unavailable" instead of failing the whole pack.
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import ipaddress
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ai.behavioral_analysis.url_analyzer import analyze_url, defang, refang, registrable_domain
from backend.app.security import get_db, rate_limit

router = APIRouter(prefix="/api", tags=["evidence"])
log = logging.getLogger("mirqab.evidence")
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RDAP = "https://rdap.org"
_cache: dict[str, tuple[float, dict]] = {}
TRANSPORT = None   # tests inject an httpx.MockTransport


class LinkIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _rdap_get(path: str) -> dict | None:
    """GET an RDAP record; follows redirects only to other HTTPS hosts; 8 s timeout; 512 KB cap."""
    key = path
    hit = _cache.get(key)
    if hit and hit[0] > time.time() - 3600:
        return hit[1]
    try:
        with httpx.Client(timeout=8, follow_redirects=True, transport=TRANSPORT, headers={"Accept": "application/rdap+json"}) as c:
            with c.stream("GET", RDAP + path) as r:
                if r.status_code != 200 or not str(r.url).startswith("https://"):
                    return None
                buf = b""
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > 512 * 1024:
                        return None
        data = json.loads(buf)
    except Exception as e:
        log.info("RDAP %s unavailable: %s", path, type(e).__name__)
        return None
    _cache[key] = (time.time(), data)
    return data


def _vcard(entity: dict, field: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return str(item[3])[:200]
    return None


def _entities(obj: dict, role: str) -> list[dict]:
    out = []
    for e in obj.get("entities") or []:
        if role in (e.get("roles") or []):
            out.append(e)
        out += _entities(e, role)
    return out


def _abuse(obj: dict) -> str | None:
    for e in _entities(obj, "abuse"):
        mail = _vcard(e, "email")
        if mail:
            return mail
    return None


def _events(obj: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate") for e in obj.get("events") or [] if e.get("eventAction")}


def domain_record(domain: str) -> dict:
    d = _rdap_get(f"/domain/{domain}")
    if not d:
        return {"status": "unavailable"}
    ev = _events(d)
    reg = next(iter(_entities(d, "registrar")), {})
    created = ev.get("registration")
    age = None
    if created:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
        except ValueError:
            age = None
    return {"status": "ok", "registrar": _vcard(reg, "fn"), "registrar_iana_id": next((p.get("identifier") for p in reg.get("publicIds") or []), None),
            "registered": created, "expires": ev.get("expiration"), "last_changed": ev.get("last changed"),
            "age_days": age, "newly_registered": age is not None and age < 30,
            "status_codes": (d.get("status") or [])[:8], "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers") or []][:6],
            "abuse_email": _abuse(d), "source": "RDAP (rdap.org)"}


def ip_record(ip: str) -> dict:
    d = _rdap_get(f"/ip/{ip}")
    if not d:
        return {"ip": ip, "status": "unavailable"}
    org = next(iter(_entities(d, "registrant")), {})
    return {"ip": ip, "status": "ok", "network": d.get("name"), "handle": d.get("handle"), "country": d.get("country"),
            "range": f"{d.get('startAddress')} – {d.get('endAddress')}" if d.get("startAddress") else None,
            "organisation": _vcard(org, "fn"), "abuse_email": _abuse(d), "source": "RDAP (rdap.org)"}


def resolve(host: str) -> list[str]:
    with cf.ThreadPoolExecutor(1) as ex:
        try:
            infos = ex.submit(socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM).result(timeout=4)
        except Exception:
            return []
    return sorted({i[4][0] for i in infos})[:6]


@router.post("/evidence/link", dependencies=[rate_limit("evidence_link", 0.34)])
def evidence_link(body: LinkIn, request: Request, db=Depends(get_db)):
    raw = refang(body.url.strip())
    url = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else "http://" + raw
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and not HOST_RE.match(host):
        raise HTTPException(422, "Not a valid web address")
    checked_at = _now()
    rep = analyze_url(url)
    reg = host if is_ip else registrable_domain(host)
    ips = [host] if is_ip else resolve(host)
    public_ips = [i for i in ips if ipaddress.ip_address(i).is_global]
    with cf.ThreadPoolExecutor(3) as ex:
        dom_f = None if is_ip else ex.submit(domain_record, reg)
        ip_fs = [ex.submit(ip_record, i) for i in public_ips[:2]]
        domain = dom_f.result() if dom_f else {"status": "not_applicable"}
        hosting = [f.result() for f in ip_fs]
    radar = [dict(r) for r in db.execute(
        "SELECT host, sources, status, first_seen, last_seen, active FROM radar_items WHERE host=? OR registrable_domain=? ORDER BY first_seen LIMIT 5",
        (host, reg))]
    signals = [{"en": s.en, "ar": s.ar, "weight": s.weight} for s in rep.signals]
    if domain.get("newly_registered"):
        signals.insert(0, {"en": f"Domain registered only {domain['age_days']} day(s) ago — most phishing domains are used within days of registration",
                           "ar": f"سُجّل النطاق قبل {domain['age_days']} يوم فقط — معظم نطاقات التصيّد تُستخدم خلال أيام من تسجيلها", "weight": 15})
    fingerprint = hashlib.sha256(f"{url}|{checked_at}".encode()).hexdigest()
    abuse = sorted({x for x in [domain.get("abuse_email"), *[h.get("abuse_email") for h in hosting]] if x})
    return {
        "pack_id": "MQ-" + fingerprint[:12].upper(), "generated_at": checked_at, "sha256": fingerprint,
        "url": {"defanged": defang(url), "host": host.replace(".", "[.]"), "registrable_domain": reg.replace(".", "[.]")},
        "analysis": {"score": rep.score, "level": rep.level, "impersonated_brand": rep.impersonated_brand,
                     "redirect_target": rep.redirect_target, "official_domain": rep.official_domain, "signals": signals},
        "registration": domain, "dns": {"resolved": ips, "private_only": bool(ips) and not public_ips}, "hosting": hosting,
        "radar": radar, "abuse_contacts": abuse,
        "method": {"en": "The suspicious website was not opened. Data comes from public registration (RDAP) and DNS records at the time shown.",
                   "ar": "لم يُفتح الموقع المشبوه. البيانات من سجلات التسجيل العامة (RDAP) وDNS في الوقت المبيّن."},
    }
