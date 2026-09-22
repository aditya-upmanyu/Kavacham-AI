"""
parsers/url_extractor.py
========================
URL extraction & structural analysis utilities for the unified engine.

Safely parses URLs (without fetching them) into their structural pieces so
analyzers can evaluate scheme, hostname, path, encoding, punycode/IDN
characteristics and suspicious domain patterns.

No network access happens here — reputation lookups live in
`intel/virustotal_service.py` (backend only).
"""

import os
import re
from urllib.parse import urlparse, unquote


# Common URL shorteners (content cannot be judged by the short domain alone,
# but presence is a transparency signal worth reporting).
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "v.gd", "s.id", "su.pr", "z.pe", "linktr.ee", "urlzs.com", "bc.vc",
}

# Riskier TLDs that phishing payloads commonly abuse.
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".online", ".site", ".buzz", ".cam", ".icu", ".rest",
    ".zip", ".mov", ".mp3", ".country", ".live", ".stream", ".racing",
    ".win", ".bid", ".men", ".loan", ".download",
}

# TLDs handled by the classic "public suffix" approach for the quick check.
SPECIAL_TLDS = {"co.uk", "co.in", "co.jp", "com.au", "org.uk", "ac.in", "gov.in", "com.pk"}


def extract_urls_from_text(text: str, limit: int = 60) -> list:
    """Extract candidate URLs from plain text with a basic regex."""
    if not text:
        return []
    pattern = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
    found = []
    for m in pattern.findall(text):
        u = m.rstrip(".,;:!?)]}>'\"")
        if u not in found:
            found.append(u)
        if len(found) >= limit:
            break
    return found


def normalize_url(url: str) -> str:
    """Ensure a URL has an explicit scheme."""
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def decode_obfuscation(url: str) -> tuple:
    """
    Detect excessive encoding / obfuscation.
    Returns (flag, decoded_once).
    """
    decoded = url
    pct_count = url.count("%")
    decoded_once = unquote(url)
    is_encoded = pct_count > 5 or decoded_once != url
    return is_encoded, decoded_once


def registrable_domain(hostname: str) -> str:
    """
    Quick heuristic for the effective second-level domain. This is not a full
    public-suffix implementation; it is intentionally conservative.
    """
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in SPECIAL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def analyze_url_structure(url: str) -> dict:
    """
    Structurally analyze a URL. Never fetches the URL.

    Returns a dict with scheme, hostname, domain, port, path, query,
    ip_address flag, punycode flag, non_ascii flag, length, shortened flag,
    suspicious_tld flag, encoded flag, and a list of structural findings.
    """
    normalized = normalize_url(url)
    findings = []
    try:
        parsed = urlparse(normalized)
    except Exception:
        parsed = None

    if parsed is None:
        return {"url": url, "valid": False, "findings": ["URL could not be parsed"]}

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    if not hostname:
        return {"url": url, "valid": False, "findings": ["URL has no hostname"]}

    domain = registrable_domain(hostname)
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    is_ip = bool(ip_pattern.match(hostname)) or hostname.startswith("[")
    is_punycode = "xn--" in hostname
    is_non_ascii = bool(re.search(r"[^\x00-\x7f]", hostname))
    is_shortened = domain in URL_SHORTENERS
    is_susp_tld = any(hostname.endswith(t) for t in SUSPICIOUS_TLDS)
    is_encoded, _ = decode_obfuscation(normalized)
    is_https = scheme == "https" and not is_ip

    if is_ip:
        findings.append("Host is a raw IP address rather than a domain name")
    if is_punycode:
        findings.append("Internationalized (punycode) domain detected — visually confusable domains are common in phishing")
    if is_non_ascii:
        findings.append("Domain contains non-ASCII characters (possible homograph attack)")
    if is_shortened:
        findings.append("URL is shortened — destination is obscured")
    if is_susp_tld:
        findings.append(f"Domain uses a frequently-abused TLD ({hostname.rsplit('.', 1)[-1]})")
    if is_encoded:
        findings.append("URL contains heavy percent-encoding (possible obfuscation)")
    if not is_https:
        findings.append("URL does not use HTTPS")

    return {
        "url": normalized,
        "valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "domain": domain,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "url_length": len(normalized),
        "is_ip": is_ip,
        "is_punycode": is_punycode,
        "is_non_ascii": is_non_ascii,
        "is_shortened": is_shortened,
        "suspicious_tld": is_susp_tld,
        "is_encoded": is_encoded,
        "is_https": is_https,
        "findings": findings,
    }