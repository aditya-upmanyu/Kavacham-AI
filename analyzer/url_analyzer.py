"""
analyzer/url_analyzer.py
========================
Malicious URL analyzer — structurally inspects every unique URL found in the
email (scheme, host, port, path, encoding, IDN/punycode, shorteners,
suspicious TLDs, IP hosts) and optionally consults VirusTotal reputation
through the backend-only intel service.

Never fetches URLs. Do not claim a URL malicious purely because it is
unfamiliar — flags must map to concrete structural anomalies or intel verdicts.
"""

from . import build_result, status_from_score, severity_from_score
from parsers.url_extractor import analyze_url_structure, normalize_url

MAX_VT_LOOKUPS = 5  # cap external calls per analysis


class _Cache:
    """Run-local cache so identical URLs/hashes are looked up once."""

    def __init__(self):
        self.urls = {}
        self.hashes = {}


def _structural_points(structure: dict) -> list:
    """Map structural anomalies to deterministic points."""
    points = []
    if structure.get("is_ip"):
        points.append(("ip_host", 26, "high", f"Host {structure['hostname']} is a raw IP address."))
    if structure.get("is_punycode"):
        points.append(("punycode", 20, "medium", f"Punycode/IDN host '{structure['hostname']}' can spoof brands."))
    if structure.get("is_encoded"):
        points.append(("excessive_encoding", 20, "medium", "Heavy percent-encoding (URL obfuscation)."))
    if structure.get("suspicious_tld"):
        points.append(("abused_tld", 18, "medium", "Popular-abused TLD present."))
    if structure.get("is_shortened"):
        points.append(("shortener", 10, "low", "URL is shortened; destination hidden."))
    if not structure.get("is_https"):
        points.append(("insecure_scheme", 8, "low", "URL does not use HTTPS."))
    if structure.get("is_non_ascii"):
        points.append(("non_ascii", 16, "medium", "Non-ASCII hostname (homograph risk)."))
    return points


def _intel_points(intel: dict) -> list:
    """Map VirusTotal verdict to points (only when intel was available)."""
    if not intel or not intel.get("available"):
        return []
    verdict = intel.get("verdict", "unknown")
    if verdict == "malicious":
        return [("vt_malicious", 40, "critical",
                 "VirusTotal flags this URL/file as malicious.")]
    if verdict == "suspicious":
        return [("vt_suspicious", 24, "high",
                 "VirusTotal reports suspicious reputation.")]
    return []


def _points_to_score(points) -> int:
    total = sum(p[1] for p in points)
    return min(100, total)


def analyze(email, vt_lookup=None, cache=None):
    """
    Analyze all unique URLs in the email.

    vt_lookup: optional callable(url) -> intel dict (from virustotal_service).
    """
    cache = cache or _Cache()
    urls = []
    url_scores = []

    for raw_url in (email.urls or []):
        norm = normalize_url(raw_url)
        structure = analyze_url_structure(norm)
        if not structure.get("valid"):
            continue

        points = _structural_points(structure)

        # VirusTotal reputation (deduped + capped)
        if vt_lookup and structure["domain"] not in cache.urls:
            try:
                intel = vt_lookup(norm)
                cache.urls[structure["domain"]] = intel
            except Exception:
                intel = None
        elif vt_lookup:
            intel = cache.urls.get(structure["domain"])
        else:
            intel = None

        points.extend(_intel_points(intel))
        score = _points_to_score(points)

        url_scores.append(score)
        urls.append({
            "url": norm,
            "hostname": structure["hostname"],
            "domain": structure["domain"],
            "scheme": structure["scheme"],
            "port": structure["port"],
            "path": (structure["path"] or "")[:60],
            "url_length": structure["url_length"],
            "risk": "critical" if score >= 75 else ("high" if score >= 50 else
                   ("medium" if score >= 25 else ("low" if score >= 10 else "none"))),
            "reputation": (intel or {}).get("verdict", "unknown") if intel else "unavailable",
            "intel_available": bool(intel and intel.get("available")),
            "intel_note": (intel or {}).get("note", "") if intel else "",
            "findings": structure.get("findings", []),
            "score": score,
        })

    if not urls:
        return build_result("clean", "none", 0, [], "No URLs found in the email.",
                            analyzed=[], intel_unavailable=bool(vt_lookup is None))

    # Aggregate: worst-case weighted toward the mean of top 3
    top = sorted(url_scores, reverse=True)[:3]
    aggregate = min(100, int(0.6 * top[0] + 0.4 * (sum(top) / len(top)))) if top else 0

    indicators = []
    for u in urls:
        if u["score"] >= 25:
            indicators.append({
                "type": "suspicious_url",
                "evidence": f"URL '{u['url'][:70]}' (host {u['hostname']}) has risk {u['risk']}"
                            f"{' — ' + u['intel_note'] if u['intel_note'] else ''}.",
                "severity": severity_from_score(u["score"]),
                "category": "url",
            })

    status = status_from_score(aggregate) if aggregate >= 20 else "clean"
    summary = f"Analyzed {len(urls)} unique URL(s). " + (
        "Suspicious URL structures or reputation flags present."
        if status == "malicious" or status == "suspicious" else "No anomalous URL structures detected."
    )

    extra = {
        "analyzed": urls,
        "url_count": len(urls),
        "intel_unavailable": not (vt_lookup is not None),
    }
    return build_result(status, severity_from_score(aggregate), aggregate, indicators, summary, **extra)