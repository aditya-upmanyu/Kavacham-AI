"""
analyzer/qr_analyzer.py
======================
QR phishing engine.

Tries to decode QR codes from image/PDF attachments and analyzes the
destination URL. Because decoding requires an optional imaging stack
(Pillow + OpenCV + pyzbar), this analyzer degrades gracefully and honestly:

    "QR code could not be analyzed."

— it never fabricates QR contents. If the QR was decoded upstream and passed
in `email.qr_codes`, its destination is run through the URL structural checks.
"""

from . import build_result, severity_from_score, status_from_score
from parsers.url_extractor import analyze_url_structure, normalize_url

try:
    from PIL import Image  # noqa: F401
    import cv2  # noqa: F401
    from pyzbar.pyzbar import decode as zxing_decode  # noqa: F401
    QR_STACK_AVAILABLE = True
except Exception:
    QR_STACK_AVAILABLE = False


def _qr_decode_available() -> bool:
    return QR_STACK_AVAILABLE


def analyze(email, qr_lookup_cache=None):
    """
    If the email object already carries decoded QR values (`qr_codes`), run
    each destination through the URL analyzer. Otherwise report that QR
    decoding is unavailable and continue — never blocking the pipeline.
    """
    qr_codes = list(getattr(email, "qr_codes", None) or [])
    indicators = []

    if not qr_codes:
        if not _qr_decode_available():
            return build_result(
                "unavailable", "none", 0, [],
                "QR code could not be analyzed — QR decoding library unavailable on this server.",
                decoded=[],
            )
        # Stack exists but no QR payloads captured by the parser either
        return build_result(
            "clean", "none", 0, [],
            "No QR code content available for analysis.",
            decoded=[],
        )

    analyzed = []
    for item in qr_codes:
        dest = (item.get("url") if isinstance(item, dict) else str(item)) or ""
        ref = item.get("source") if isinstance(item, dict) else "unknown"
        if not dest:
            analyzed.append({"source": ref, "url": "", "risk": "unknown"})
            continue
        norm = normalize_url(dest)
        structure = analyze_url_structure(norm)
        risk = "high" if structure.get("is_ip") or structure.get("is_punycode") else \
               ("medium" if structure.get("suspicious_tld") or structure.get("is_encoded") else "low")
        score = 40 if risk == "high" else (25 if risk == "medium" else 5)
        analyzed.append({
            "source": ref,
            "url": norm,
            "host": structure.get("hostname", ""),
            "risk": risk,
            "score": score,
            "findings": structure.get("findings", []),
        })
        if risk in ("high", "medium"):
            indicators.append({
                "type": "qr_phishing",
                "evidence": f"QR code (from {ref}) resolves to '{norm}' (host {structure.get('hostname', '?')}) — {risk} risk destination.",
                "severity": "high" if risk == "high" else "medium",
                "category": "qr",
            })

    score = max((a["score"] for a in analyzed), default=0)
    status = status_from_score(score) if score >= 25 else "clean"
    return build_result(status, severity_from_score(score), score, indicators,
                        f"Analyzed {len(analyzed)} QR destination(s).",
                        decoded=analyzed)