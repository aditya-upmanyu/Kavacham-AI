"""
analyzer/attachment_analyzer.py
===============================
Attachment security engine — analyzes metadata (filename, extension, MIME,
size, SHA-256 hash) and optionally checks hashes against VirusTotal.

Files are NEVER executed. Content is not extracted beyond what the parser
already captured (hash only). For archives, only the archive format is
reported — no internal extraction is performed.
"""

from . import build_result, severity_from_score, sum_indicators, status_from_score
from parsers.attachment_parser import analyze_attachment_extension

MAX_HASH_LOOKUPS = 5


class _Cache:
    """Run-local cache so identical hashes are looked up once."""

    def __init__(self):
        self.hashes = {}


def analyze(email, vt_hash_lookup=None, cache=None):
    cache = cache or _Cache()
    attachments = email.attachments or []
    indicators = []
    analyzed = []

    for att in attachments:
        ext_result = analyze_attachment_extension(att.filename)

        entry = {
            "filename": att.filename,
            "mime_type": att.mime_type or "Unknown",
            "size": att.size,
            "sha256": att.sha256 or "unavailable",
            "extension": ext_result["extension"],
            "risk": ext_result["risk"],
            "risk_reason": ext_result["reason"],
        }

        # Optional VirusTotal hash reputation (deduped + capped)
        if vt_hash_lookup and att.sha256 and att.sha256 not in cache.hashes:
            try:
                intel = vt_hash_lookup(att.sha256)
                cache.hashes[att.sha256] = intel
            except Exception:
                intel = {"available": False, "note": "VirusTotal lookup failed."}
        elif vt_hash_lookup:
            intel = cache.hashes.get(att.sha256)
        else:
            intel = None

        if intel:
            entry["reputation"] = intel.get("verdict", "unavailable")
            entry["intel_note"] = intel.get("note", "")
            entry["intel_available"] = bool(intel.get("available"))
        else:
            entry["reputation"] = "unavailable"
            entry["intel_note"] = ""
            entry["intel_available"] = False

        if ext_result["risky"]:
            indicators.append({
                "type": "risky_attachment",
                "evidence": (
                    f"Attachment '{att.filename}' ({att.mime_type or 'unknown'} type, "
                    f"{att.size} bytes) — {ext_result['reason']}."
                ),
                "severity": "critical" if ext_result["risk"] == "critical" else
                            ("high" if ext_result["risk"] == "high" else "medium"),
                "category": "attachment",
            })
        elif intel and intel.get("verdict") in ("malicious", "suspicious") and intel.get("available"):
            indicators.append({
                "type": "vt_hash_flag",
                "evidence": f"Attachment '{att.filename}' hash {att.sha256[:12]}… flagged by VirusTotal as {intel['verdict']}.",
                "severity": "high" if intel.get("verdict") == "malicious" else "medium",
                "category": "attachment",
            })
        analyzed.append(entry)

    score = sum_indicators([i["severity"] for i in indicators])
    status = status_from_score(score) if score >= 20 else "clean"
    status = "malicious" if score >= 50 else status

    if not attachments:
        summary = "No attachments in this message."
    elif indicators:
        summary = f"{len(indicators)} risky or flagged attachment(s) detected."
    else:
        summary = f"{len(attachments)} attachment(s) reviewed — no risk flags found."

    return build_result(status, severity_from_score(score), score, indicators, summary,
                        attachments=analyzed,
                        hash_lookups_done=len(cache.hashes),
                        intel_unavailable=not bool(vt_hash_lookup))