"""KAVACHAM LAB — RDAP + DNS network intelligence (Section AG).

Keyless and passive: DNS answers come from DNS-over-HTTPS reads and RDAP
from the public IANA bootstrap — no active probing, no intrusive
scanning. Every lookup carries an 8s timeout (BS) and degrades to an
honest `unavailable` state offline. Only stdlib (urllib/json/socket).
"""

import json
import socket
import urllib.parse
import urllib.request

TIMEOUT_S = 8
DOH_URL = "https://cloudflare-dns.com/dns-query"
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns"
DKIM_SELECTORS = ("default", "google", "k1", "selector1", "selector2")


def _https_json(url, params=None):
    """GET a JSON endpoint with a hard timeout. Raises on any failure."""
    target = url + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(
        target, headers={"Accept": "application/json",
                         "User-Agent": "KAVACHAM-LAB/1.0 (RDAP+DNS)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _doh(name, rtype):
    """DNS-over-HTTPS answer values for one record type, [] on failure."""
    try:
        body = _https_json(DOH_URL, {"name": name, "type": rtype})
    except Exception:
        return []
    out = []
    for ans in body.get("Answer") or []:
        data = (ans.get("data") or "").strip().strip('"')
        if data:
            out.append(data)
    return out


def dns_lookup(domain):
    """A/AAAA/MX/NS/CNAME/TXT + derived SPF/DMARC/DKIM (best effort)."""
    host = (domain or "").strip().strip(".").lower()
    if not host or "." not in host or " " in host:
        return {"state": "invalid",
                "note": "Not a plausible domain name."}
    records = {}
    try:
        for rtype in ("A", "AAAA", "MX", "NS", "CNAME", "TXT"):
            records[rtype] = _doh(host, rtype)
    except Exception:
        return {"state": "unavailable",
                "note": "DNS resolver unreachable (offline?)."}
    if not any(records.values()):
        # Fall back to the local resolver before declaring unavailable:
        # proves whether the name exists at all without new dependencies.
        try:
            info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                      type=socket.SOCK_STREAM)
            addrs = sorted({i[4][0] for i in info})
            if addrs:
                records["A"] = addrs
        except Exception:
            return {"state": "unavailable",
                    "note": "No DNS answers for %s." % host}
        if not any(records.values()):
            return {"state": "unavailable",
                    "note": "No DNS answers for %s." % host}
    txts = records.get("TXT", [])
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    dmarc = _doh("_dmarc." + host, "TXT")
    dkim = {}
    for selector in DKIM_SELECTORS:
        vals = _doh("%s._domainkey.%s" % (selector, host), "TXT")
        if vals:
            dkim[selector] = vals
    return {"state": "available", "domain": host, "records": records,
            "spf": spf,
            "dmarc": [t for t in dmarc if t.lower().startswith("v=dmarc1")],
            "dkim": dkim, "dkim_selectors_checked": list(DKIM_SELECTORS),
            "note": "Passive DNS reads only; no active probing."}


def _rdap_service_url(tld):
    body = _https_json(IANA_BOOTSTRAP)
    for svc in body.get("services") or []:
        zones, urls = svc
        if tld in [z.lower().rstrip(".") for z in zones] and urls:
            return urls[0]
    return None


def rdap_lookup(domain):
    """Registrar/dates/status/nameservers/entities via the IANA bootstrap."""
    host = (domain or "").strip().strip(".").lower()
    if not host or "." not in host or " " in host:
        return {"state": "invalid",
                "note": "Not a plausible domain name."}
    tld = host.rsplit(".", 1)[-1]
    try:
        base = _rdap_service_url(tld)
        if not base:
            return {"state": "unavailable",
                    "note": "No RDAP service published for .%s." % tld}
        body = _https_json(base.rstrip("/") + "/domain/" + host)
    except Exception:
        return {"state": "unavailable",
                "note": "RDAP unreachable for %s (offline?)." % host}
    events = {e.get("eventAction"): e.get("eventDate")
              for e in body.get("events") or [] if e.get("eventAction")}
    registrar = None
    entities = []
    for ent in body.get("entities") or []:
        roles = ent.get("roles") or []
        handle = ent.get("handle")
        name = None
        for v in ent.get("vcardArray", [None, []])[1] or []:
            if isinstance(v, list) and v and v[0] == "fn":
                name = v[3] if len(v) > 3 else name
        entities.append({"handle": handle, "roles": roles, "name": name})
        if "registrar" in roles and registrar is None:
            registrar = name or handle
    return {"state": "available", "domain": host,
            "registrar": registrar,
            "creation_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": body.get("status") or [],
            "nameservers": sorted({
                (ns.get("ldhName") or "").lower()
                for ns in body.get("nameservers") or []
                if ns.get("ldhName")}),
            "entities": entities,
            "note": "Public RDAP data only."}


def lookup(domain):
    """Combined AG lookup: {"dns": ..., "rdap": ...} (never raises)."""
    try:
        dns = dns_lookup(domain)
    except Exception:
        dns = {"state": "unavailable", "note": "DNS lookup failed."}
    try:
        rdap = rdap_lookup(domain)
    except Exception:
        rdap = {"state": "unavailable", "note": "RDAP lookup failed."}
    return {"dns": dns, "rdap": rdap}
