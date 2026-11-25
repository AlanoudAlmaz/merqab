"""Parse Certificate Transparency (RFC 6962) get-entries responses into domain names."""
from __future__ import annotations

import base64
import struct

from cryptography import x509
from cryptography.x509.oid import NameOID


def _names_from_der(der: bytes) -> list[str]:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return []
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names += san.get_values_for_type(x509.DNSName)
    except Exception:
        pass
    try:
        names += [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    except Exception:
        pass
    return names


def entry_details(entry: dict) -> tuple[list[str], int | None, str | None]:
    """(domains, certificate timestamp in ms from the log leaf, issuer common name)."""
    try:
        leaf = base64.b64decode(entry["leaf_input"])
        ts = struct.unpack(">Q", leaf[2:10])[0] if len(leaf) >= 10 else None
    except (KeyError, ValueError):
        return [], None, None
    issuer = None
    der = _der(entry)
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer = cn[0].value if cn else None
        except Exception:
            pass
    return domains_from_entry(entry), ts, issuer


def _der(entry: dict) -> bytes:
    try:
        leaf = base64.b64decode(entry["leaf_input"])
        extra = base64.b64decode(entry.get("extra_data", ""))
    except (KeyError, ValueError):
        return b""
    if len(leaf) < 15:
        return b""
    et = struct.unpack(">H", leaf[10:12])[0]
    if et == 0:
        return leaf[15:15 + int.from_bytes(leaf[12:15], "big")]
    if et == 1 and len(extra) > 3:
        return extra[3:3 + int.from_bytes(extra[0:3], "big")]
    return b""


def domains_from_entry(entry: dict) -> list[str]:
    """Return de-duplicated, lower-case DNS names (wildcards stripped) for one CT log entry."""
    try:
        leaf = base64.b64decode(entry["leaf_input"])
        extra = base64.b64decode(entry.get("extra_data", ""))
    except (KeyError, ValueError):
        return []
    if len(leaf) < 15:
        return []
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    der = b""
    if entry_type == 0:  # x509_entry: 3-byte length + certificate
        n = int.from_bytes(leaf[12:15], "big")
        der = leaf[15:15 + n]
    elif entry_type == 1 and len(extra) > 3:  # precert: full pre-certificate is first in extra_data
        n = int.from_bytes(extra[0:3], "big")
        der = extra[3:3 + n]
    out = []
    for name in _names_from_der(der):
        d = name.strip().lower().lstrip("*.").rstrip(".")
        if d and "." in d and d not in out and all(c.isalnum() or c in "-." for c in d.replace("xn--", "")):
            out.append(d)
    return out
