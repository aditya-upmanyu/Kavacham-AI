"""
lab/analysis_service.py
========================
KAVACHAM LAB — Phase 7 analysis pipeline (Sections 29-41).

Every analysis type is backed by a REAL engine:

  integrated from Product A (reused, never duplicated):
    EMAIL     -> analyzer.email_analyzer.analyze_email (full unified pipeline:
                 spam ML + phishing + url + sender + header + scam + bec +
                 attachment + qr + deterministic risk engine)
    PHISHING  -> analyzer.phishing_analyzer.analyze
    SPAM      -> analyzer.spam_analyzer.analyze        (real Product A model)
    URL       -> parsers.url_extractor (normalize / structure) + VirusTotal
    SCAM      -> analyzer.scam_analyzer.analyze
    BEC       -> analyzer.bec_analyzer.analyze

  Lab-native runners (real local computation only):
    FILE      -> magic/extension/MIME consistency + embedded URL extraction
                 + optional VirusTotal hash intel
    HASH      -> format validation + local vault correlation + optional
                 VirusTotal hash intel
    QR        -> decode stored image (pyzbar if present) -> URL structure
    DOMAIN    -> registrable-domain + structure + optional VirusTotal intel

No fabricated verdicts, latencies or confidence. External intelligence is
only consulted when configured; otherwise the run reports it honestly
(NOT CONFIGURED) while local analysis still completes (Section 41/63).
"""

import json
import os
import re
from datetime import datetime, timezone

from lab import db
from lab import case_service
from lab import evidence_service
from lab import network_intel

ACTOR_DEFAULT = "analyst"

MAX_FINDINGS = 60

# ---------------------------------------------------------------------------
# Analysis type registry (Section 47 ordering; matches the ANALYSIS nav group)
# ---------------------------------------------------------------------------

ANALYSIS_TYPES = [
    "EMAIL", "PHISHING", "SPAM", "URL", "FILE", "HASH",
    "QR", "DOMAIN", "SCAM", "BEC", "SMS",
]

ANALYSIS_REGISTRY = {
    "EMAIL": {
        "label": "Email Forensics",
        "description": ("Full unified email pipeline: spam ML classification, "
                        "phishing, URL, sender, headers, scam, BEC, attachment "
                        "and QR detectors feeding the deterministic risk engine."),
        "evidence_types": ["EMAIL", "RAW_HEADER", "MESSAGE"],
    },
    "PHISHING": {
        "label": "Phishing Check",
        "description": "Phishing detection engine over the email content.",
        "evidence_types": ["EMAIL", "RAW_HEADER", "MESSAGE", "URL"],
    },
    "SPAM": {
        "label": "Spam Classification",
        "description": "Kavacham AI ML spam classifier (real model inference).",
        "evidence_types": ["EMAIL", "RAW_HEADER", "MESSAGE"],
    },
    "URL": {
        "label": "URL Analysis",
        "description": ("URL normalization, structural feature extraction and "
                        "optional VirusTotal reputation lookup."),
        "evidence_types": ["URL", "EMAIL", "RAW_HEADER", "MESSAGE",
                           "DOMAIN", "IP", "FILE"],
    },
    "FILE": {
        "label": "File & Hash Analysis",
        "description": ("Local file inspection (extension/MIME consistency, "
                        "blocked content, embedded URLs) plus optional "
                        "VirusTotal hash intelligence."),
        "evidence_types": ["FILE", "SCREENSHOT", "QR_IMAGE"],
    },
    "HASH": {
        "label": "Hash Analysis",
        "description": ("Hash format validation, local vault correlation and "
                        "optional VirusTotal hash intelligence."),
        "evidence_types": ["HASH"],
    },
    "QR": {
        "label": "QR / Quishing",
        "description": "Decode the stored QR image and analyze destinations.",
        "evidence_types": ["QR_IMAGE", "SCREENSHOT", "FILE"],
    },
    "DOMAIN": {
        "label": "Domain Analysis",
        "description": ("Domain structure, registrable-domain extraction, "
                        "suspicious feature detection, keyless DNS + RDAP "
                        "network intelligence, and optional VirusTotal "
                        "reputation lookup."),
        "evidence_types": ["DOMAIN", "URL", "IP", "EMAIL", "RAW_HEADER",
                           "MESSAGE"],
    },
    "SCAM": {
        "label": "Scam Analysis",
        "description": "Financial / UPI / KYC / investment / delivery / job / "
                       "tech-support / digital-arrest scam detection.",
        "evidence_types": ["EMAIL", "RAW_HEADER", "MESSAGE"],
    },
    "BEC": {
        "label": "BEC / Fraud Analysis",
        "description": "Business email compromise and fraud indicators.",
        "evidence_types": ["EMAIL", "RAW_HEADER", "MESSAGE"],
    },
    "SMS": {
        "label": "SMS / Smishing Analysis",
        "description": "SMS, WhatsApp and chat text: ML spam classification "
                       "plus scam-family signals (OTP, KYC, UPI, delivery, "
                       "job, loan, credential theft).",
        "evidence_types": ["MESSAGE"],
    },
}


class AnalysisError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def reference_data():
    return {
        "types": ANALYSIS_TYPES,
        "registry": {t: {k: v for k, v in spec.items() if k != "description"}
                     for t, spec in ANALYSIS_REGISTRY.items()},
        "evidence_types": evidence_service.EVIDENCE_TYPES,
    }


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_analysis_ref():
    year = _now()[:4]
    ref = "KAV-ANL-%s-00001" % year
    seq = 1
    while True:
        existing = db.query_one(
            "SELECT 1 AS x FROM analyses WHERE analysis_ref = ?", (ref,))
        if not existing:
            return ref
        seq += 1
        ref = "KAV-ANL-%s-%05d" % (year, seq)


# ---------------------------------------------------------------------------
# Lazy Product A integration (no import cost until a run actually needs it)
# ---------------------------------------------------------------------------

def _predict_spam_fn():
    """Return the real Product A ML callable, or None when unavailable."""
    try:
        from app import predict_spam  # noqa: E402
        return predict_spam
    except Exception:
        return None


def _stub_predict(raw_text):
    raise ValueError("ML classifier unavailable in this environment.")


def _ml_probe():
    """Probe the real Product A classifier. Returns (callable, ready).

    ready is True only when a real inference actually succeeded end-to-end,
    so the 'Local ML analysis' stage label is never fabricated (Section 63).
    """
    predict = _predict_spam_fn()
    if predict is None:
        return _stub_predict, False
    try:
        predict("model-readiness-probe-text")
        return predict, True
    except Exception:
        return _stub_predict, False


_FROM_RE = re.compile(r"^From\s*:", re.IGNORECASE | re.MULTILINE)


def _looks_like_rfc822(text):
    return bool(_FROM_RE.search(text)) and any(
        re.search(r"^%s\s*:" % h, text, re.IGNORECASE | re.MULTILINE)
        for h in ("Subject", "Date", "Reply-To", "Return-Path", "Message-ID"))


def _normalized_email(ev, url_hint=None):
    """Build a Product A NormalizedEmail from evidence content. Real parsing."""
    from parsers.email_parser import NormalizedEmail, parse_address
    from parsers.url_extractor import extract_urls_from_text

    raw = (ev.get("content_text") or "").strip()
    subject = ev.get("title") or "(No Subject)"
    sender_raw = "Unknown Sender"
    headers = {}
    body = raw

    if _looks_like_rfc822(raw):
        from email import message_from_string
        try:
            msg = message_from_string(raw)
            headers = {str(k).lower(): (str(v) or "").strip()
                       for k, v in msg.items()}
            sender_raw = headers.get("from", "") or "Unknown Sender"
            payload = msg.get_payload()
            if isinstance(payload, str):
                body = payload.strip()
            elif isinstance(payload, list):
                parts = []
                for part in payload:
                    try:
                        txt = part.get_payload(decode=True)
                        mime = str(part.get_content_type() or "")
                        if txt and mime in ("text/plain", "text/html"):
                            parts.append(txt.decode("utf-8", "replace"))
                    except Exception:
                        continue
                body = "\n".join(parts).strip() or raw
        except Exception:
            body = raw
        subject = headers.get("subject") or subject

    sender_name, sender_email, sender_domain = parse_address(sender_raw)
    reply_to_raw = headers.get("reply-to", "") or ""
    _, reply_to_email, reply_to_domain = parse_address(reply_to_raw)
    return_path = headers.get("return-path", "") or ""

    urls = extract_urls_from_text(body, limit=60)
    if url_hint:
        h = str(url_hint).strip()
        if h and h not in urls:
            urls.append(h)

    return NormalizedEmail(
        id="evidence-%s" % ev.get("evidence_ref", "?"),
        sender_raw=sender_raw,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_raw=reply_to_raw,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        recipients=[r.strip() for r in headers.get("to", "").split(",")
                    if r.strip()],
        subject=subject,
        date=headers.get("date", "Unknown Date"),
        body_text=body,
        headers=headers,
        urls=urls,
        anchor_map=[{"href": u, "text": u} for u in urls[:40]],
        attachments=[],
    )


# ---------------------------------------------------------------------------
# Stage tracking (Section 41 — only stages actually performed)
# ---------------------------------------------------------------------------

class Pipeline:
    def __init__(self):
        self.stages = []
        self.findings = []
        self.payload = {}
        self.source = []
        self.engine_version = ""

    def stage(self, name, status, detail=""):
        self.stages.append({"name": name, "status": status,
                            "detail": detail or ""})

    def finding(self, finding_type, severity, title, detail, source):
        self.findings.append({
            "finding_type": finding_type or "indicator",
            "severity": severity or "low",
            "title": title or finding_type,
            "detail": detail or "",
            "source": source or self.engine_version,
        })

    def add_source(self, name):
        if name not in self.source:
            self.source.append(name)


def _indicators_to_findings(pipeline, indicators, source):
    for ind in (indicators or [])[:MAX_FINDINGS]:
        pipeline.finding(
            ind.get("type") or "indicator",
            ind.get("severity") or "low",
            (ind.get("type") or "indicator").replace("_", " ").upper(),
            ind.get("evidence") or "",
            source)


# ---------------------------------------------------------------------------
# STD panels for stage output
# ---------------------------------------------------------------------------

def _vt_state():
    try:
        from intel.virustotal_service import availability_status as vt_status
        return vt_status().get("configured", False)
    except Exception:
        return False


def _vt_lookup_hash(sha256):
    try:
        from intel.virustotal_service import lookup_hash as vt_lookup_hash
        return vt_lookup_hash(sha256)
    except Exception:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": "VirusTotal lookup failed."}


def _vt_lookup_url(url):
    try:
        from intel.virustotal_service import lookup_url as vt_lookup_url
        return vt_lookup_url(url)
    except Exception:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": "VirusTotal lookup failed."}


def _url_analyzer_email(urls):
    """Minimal NormalizedEmail carrying URLs for the real url_analyzer."""
    from parsers.email_parser import NormalizedEmail
    seen, deduped = set(), []
    for u in urls:
        u = str(u).strip()
        if u and u not in seen:
            seen.add(u)
            deduped.append(u)
    return NormalizedEmail(id="url-analysis", urls=deduped,
                           anchor_map=[{"href": u, "text": u}
                                       for u in deduped[:40]])


def _intel_verdict(verdict):
    return {
        "malicious": ("MALICIOUS", "medium"),
        "suspicious": ("SUSPICIOUS", "medium"),
        "clean": ("CLEAN", "none"),
        "no-data": ("NO_THREAT_DATA", "none"),
        "unavailable": ("UNKNOWN", "none"),
    }.get(verdict, ("UNKNOWN", "none"))


# ---------------------------------------------------------------------------
# Runners — each returns (verdict, risk_score, confidence)
# ---------------------------------------------------------------------------

def _run_email(pipeline, ev):
    from analyzer.email_analyzer import analyze_email

    predict, ml_ready = _ml_probe()
    pipeline.add_source("KAVACHAM AI unified email engine")
    pipeline.engine_version = "unified.email_analyzer.v1"

    pipeline.stage("Input normalized", "done",
                   "NormalizedEmail built from evidence")
    pipeline.stage("Indicators extracted", "done",
                   "Analyzers receive the normalized email")
    if ml_ready:
        pipeline.stage("Local ML analysis", "done", "Real model inference executed")
    else:
        pipeline.stage("Local ML analysis", "unavailable",
                       "ML classifier unavailable in this environment.")

    try:
        report = analyze_email(_normalized_email(ev), predict_spam_fn=predict,
                               ultra_ai=False)
    except Exception as exc:
        raise AnalysisError("ANALYSIS_FAILED",
                            "Email analysis failed: %s" % type(exc).__name__, 500)

    pipeline.payload = report
    security = report.get("security") or {}
    verdict = security.get("verdict") or "UNAVAILABLE"
    risk_score = int(security.get("risk_score", 0) or 0)

    intel_ok = bool((report.get("intel_status") or {}).get("virustotal_configured"))
    pipeline.stage("Threat intelligence", "done" if intel_ok else "unavailable",
                   "VirusTotal enabled" if intel_ok
                   else "VirusTotal not configured — local analysis only.")
    pipeline.stage("Risk calculation", "done",
                   "Deterministic risk engine (evidence-based).")

    for reason in report.get("top_reasons") or []:
        pipeline.finding("risk_factor", reason.get("severity") or "low",
                         "RISK DRIVER - %s" % str(reason.get("factor", "")).upper(),
                         reason.get("reason") or "", "risk_engine")
    _indicators_to_findings(pipeline, report.get("evidence") or [], "email_pipeline")

    spam = report.get("classification") or {}
    confidence = float(spam.get("confidence", 0.0) or 0.0) or None
    return verdict, risk_score, confidence


def _run_phishing(pipeline, ev):
    from analyzer import phishing_analyzer
    pipeline.add_source("phishing_analyzer")
    pipeline.engine_version = "phishing_analyzer.v1"
    pipeline.stage("Input normalized", "done", "NormalizedEmail built from evidence")
    result = phishing_analyzer.analyze(_normalized_email(ev))
    pipeline.stage("Indicators extracted", "done",
                   "Detected %d indicator(s)." % len(result.get("indicators") or []))
    pipeline.stage("Risk calculation", "done",
                   "Severity/score mapped from detected indicators.")
    pipeline.payload = result
    _indicators_to_findings(pipeline, result.get("indicators"), "phishing_analyzer")
    return (str(result.get("status") or "clean").upper(),
            int(result.get("score", 0) or 0), None)


def _run_spam(pipeline, ev):
    from analyzer import spam_analyzer
    predict, ml_ready = _ml_probe()
    pipeline.add_source("KAVACHAM AI spam ML model")
    pipeline.engine_version = "spam_analyzer.v1 (Product A model)"
    pipeline.stage("Input normalized", "done", "Subject + body extracted")

    if ml_ready:
        pipeline.stage("Local ML analysis", "done", "Real model inference executed")
        result = spam_analyzer.analyze(_normalized_email(ev), predict)
    else:
        pipeline.stage("Local ML analysis", "unavailable",
                       "ML classifier unavailable in this environment.")
        result = spam_analyzer.analyze(_normalized_email(ev), _stub_predict)

    pipeline.stage("Risk calculation", "done",
                   "Spam probability mapped to classification score.")
    pipeline.payload = result
    classification = str(result.get("classification") or "Unavailable")
    verdict = "MALICIOUS" if classification == "Spam" else \
        ("CLEAN" if classification == "Not Spam" else "UNAVAILABLE")
    _indicators_to_findings(pipeline, result.get("indicators"), "spam_analyzer")
    confidence = float(result.get("probability_spam", 0.0) or 0.0)
    return verdict, int(result.get("score", 0) or 0), confidence


def _run_url(pipeline, ev, url_hint=None):
    from analyzer.url_analyzer import analyze as url_analyze, \
        MAX_VT_LOOKUPS as url_max_lookup
    from parsers.url_extractor import normalize_url

    urls = url_hint if url_hint is not None else _extract_target_urls(ev)
    if isinstance(urls, str):
        urls = [urls]
    urls = [normalize_url(u) for u in urls[:url_max_lookup]]

    pipeline.add_source("url_pipeline.url_analyzer")
    pipeline.engine_version = "url_pipeline.v1"
    pipeline.stage("Input normalized", "done",
                   "%d URL(s) normalized." % len(urls))

    intel_configured = _vt_state()
    vt_lookup = (_vt_lookup_url if intel_configured else None)
    result = url_analyze(_url_analyzer_email(urls), vt_lookup=vt_lookup)

    status = str(result.get("status") or "clean").upper()
    verdict = {"MALICIOUS": "MALICIOUS", "SUSPICIOUS": "SUSPICIOUS",
               "CLEAN": "CLEAN", "UNAVAILABLE": "UNAVAILABLE"}.get(
                   status, status)
    risk_score = int(result.get("score", 0) or 0)
    analyzed = result.get("analyzed") or []
    analyzed_count = len(analyzed)

    _indicators_to_findings(pipeline, result.get("indicators"),
                            "url_pipeline.url_analyzer")

    if intel_configured:
        pipeline.stage("Threat intelligence", "done",
                       "%d URL(s) checked against VirusTotal."
                       % analyzed_count)
    else:
        pipeline.stage("Threat intelligence", "unavailable",
                       "VirusTotal not configured — structure analysis only.")

    pipeline.stage("Risk calculation", "done",
                   "Deterministic structural + intelligence scoring "
                   "(url_analyzer).")
    pipeline.payload = {
        "analyzed": analyzed[:10],
        "url_count": analyzed_count,
        "url_total": result.get("url_count", analyzed_count),
        "intel_configured": intel_configured,
        "summary": result.get("summary", ""),
    }
    return verdict, risk_score, None


def _run_file(pipeline, ev):
    from analyzer.url_analyzer import analyze as url_analyze
    from parsers.url_extractor import normalize_url

    stored = ev.get("stored_path")
    ext = (ev.get("extension") or "").lower()
    mime = ev.get("mime_type") or ""
    sha256 = ev.get("sha256") or ""
    size = int(ev.get("size_bytes") or 0)

    pipeline.add_source("local_file_inspector")
    pipeline.engine_version = "file_pipeline.v1"
    pipeline.stage("Input normalized", "done",
                   "Stored bytes located and metadata loaded.")

    verdict = "CLEAN"
    risk_score = 0
    confidence = None

    # 1. Blocked content signature (PE/ELF) — mirrors evidence intake.
    blocked = False
    if stored and os.path.exists(stored):
        try:
            with open(stored, "rb") as fh:
                head = fh.read(4096)
            if head[:2] in (b"MZ", b"\x7fELF"):
                blocked = True
                pipeline.finding("executable_content", "high",
                                 "EXECUTABLE CONTENT",
                                 "Stored file begins with a PE/ELF signature.",
                                 "local_file_inspector")
        except Exception:
            pass
    pipeline.stage("Blocked content scan", "done",
                   "Magic-byte scan against PE/ELF signatures.")

    # 2. Extension -> MIME consistency (real names; short-list of common types).
    ext_mime = {
        ".pdf": "application/pdf", ".txt": "text/plain", ".html": "text/html",
        ".htm": "text/html", ".csv": "text/csv", ".json": "application/json",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".zip": "application/zip",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls": "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    expected = ext_mime.get(ext)
    if expected and mime and mime != "application/octet-stream" \
            and expected != mime and ".%s" % mime.split("/")[-1] != ext:
        pipeline.finding("mime_mismatch", "low", "MIME/EXTENSION MISMATCH",
                         "Extension %s does not match detected MIME %s."
                         % (ext or "(none)", mime or "(unknown)"),
                         "local_file_inspector")

    # 3. Embedded URLs in text-like content (real url_analyzer sub-run).
    url_count = 0
    if stored and os.path.exists(stored):
        try:
            with open(stored, "rb") as fh:
                sample = fh.read(64 * 1024)
            sample_text = sample.decode("utf-8", "replace")
            from parsers.url_extractor import extract_urls_from_text
            urls = [normalize_url(u)
                    for u in extract_urls_from_text(sample_text, limit=30)]
            if urls:
                intel_configured = _vt_state()
                sub = url_analyze(_url_analyzer_email(urls),
                                  vt_lookup=(_vt_lookup_url
                                             if intel_configured else None))
                url_count = len(sub.get("analyzed") or [])
                _indicators_to_findings(pipeline, sub.get("indicators"),
                                        "file_pipeline.url_analyzer")
                pipeline.payload["url_sub_analysis"] = {
                    "summary": sub.get("summary", ""),
                    "analysis": (sub.get("analyzed") or [])[:10],
                }
        except Exception:
            pass
    pipeline.payload["url_count"] = url_count
    pipeline.stage("Embedded URL extraction", "done",
                   "%d URL(s) found in content." % url_count)

    # 4. Optional VirusTotal hash intelligence.
    intel_configured = _vt_state()
    if intel_configured and sha256:
        intel = _vt_lookup_hash(sha256)
        iv, _ = _intel_verdict(intel.get("verdict", "unavailable"))
        if intel.get("data"):
            for label in (intel["data"].get("flagged_by") or [])[:5]:
                pipeline.finding("virustotal_engine", "medium",
                                 "VIRUSTOTAL ENGINE - %s" % label.upper(),
                                 "Engine %s flagged this file hash." % label,
                                 "virustotal")
        if intel.get("data"):
            pipeline.payload["intel"] = {
                "verdict": intel.get("verdict"),
                "note": intel.get("note"),
                "data": intel.get("data"),
            }
        pipeline.stage("Threat intelligence", "done",
                       "Hash checked against VirusTotal.")
    else:
        pipeline.stage("Threat intelligence", "unavailable",
                       "VirusTotal not configured — local inspection only.")
        pipeline.payload["intel"] = {"verdict": "unavailable",
                                     "note": "VirusTotal not configured."}

    payload = pipeline.payload
    payload["blocked_content"] = blocked
    payload["size_bytes"] = size
    payload["extension"] = ext
    pipeline.stage("Risk calculation", "done", "Deterministic local scoring.")

    if blocked:
        verdict = "MALICIOUS"
        risk_score = max(risk_score, 85)
    elif any(f["severity"] in ("high", "critical") for f in pipeline.findings):
        verdict = "SUSPICIOUS"
        risk_score = max(risk_score, 51)
    return verdict, risk_score, confidence


def _run_hash(pipeline, ev):
    value = (ev.get("content_text") or "").strip()
    sha256_pattern = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
    sha1_pattern = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
    md5_pattern = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

    pipeline.add_source("hash_analyzer")
    pipeline.engine_version = "hash_pipeline.v1"
    pipeline.stage("Input normalized", "done", "Hash value extracted from evidence.")

    if sha256_pattern.match(value):
        hash_type, hash_value = "SHA-256", value.lower()
    elif sha1_pattern.match(value):
        hash_type, hash_value = "SHA-1", value.lower()
    elif md5_pattern.match(value):
        hash_type, hash_value = "MD5", value.lower()
    else:
        raise AnalysisError("INVALID_HASH",
                            "Evidence content is not a valid SHA-256, SHA-1 or "
                            "MD5 hash.", 400)

    verdict = "NO_THREAT_DATA"
    risk_score = 0
    confidence = None

    # 1. Format validation stage (Section 40 transparency).
    pipeline.stage("Indicators extracted", "done",
                   "Recognized %s hash (%d characters)." % (hash_type,
                                                            len(hash_value)))

    # 2. Local vault correlation — real: does this hash identify another
    #    stored evidence item in THIS vault?
    matches = db.query(
        "SELECT evidence_ref, evidence_type, title, sha256 FROM evidence "
        "WHERE sha256 = ? LIMIT 10", (hash_value,))
    if matches:
        for m in matches:
            pipeline.finding("local_vault_correlation", "medium",
                             "LOCAL VAULT CORRELATION",
                             "Hash matches evidence %s (%s)."
                             % (m["evidence_ref"], m["evidence_type"]),
                             "hash_analyzer")
        pipeline.stage("Local correlation", "done",
                       "%d matching evidence record(s) in this vault."
                       % len(matches))
    else:
        pipeline.stage("Local correlation", "done",
                       "No matching record in the local vault.")

    # 3. VirusTotal intelligence (only when configured).
    if _vt_state():
        intel = _vt_lookup_hash(hash_value)
        iv, isev = _intel_verdict(intel.get("verdict", "unavailable"))
        pipeline.payload["intel"] = {"verdict": intel.get("verdict"),
                                     "note": intel.get("note"),
                                     "data": intel.get("data")}
        if intel.get("data"):
            for label in (intel["data"].get("flagged_by") or [])[:5]:
                pipeline.finding("virustotal_engine", "medium",
                                 "VIRUSTOTAL ENGINE - %s" % label.upper(),
                                 "Engine %s flagged this hash." % label,
                                 "virustotal")
        if iv != "UNKNOWN":
            verdict = iv
            risk_score = max(risk_score, 75 if iv == "MALICIOUS"
                             else (45 if iv == "SUSPICIOUS" else 0))
        pipeline.stage("Threat intelligence", "done",
                       "Hash checked against VirusTotal.")
    else:
        pipeline.stage("Threat intelligence", "unavailable",
                       "VirusTotal not configured — format/local checks only.")
        pipeline.payload["intel"] = {"verdict": "unavailable",
                                     "note": "VirusTotal not configured."}

    pipeline.stage("Risk calculation", "done", "Deterministic scoring.")
    pipeline.payload.update({
        "hash_type": hash_type,
        "hash_value": hash_value,
        "local_matches": [m["evidence_ref"] for m in matches],
    })
    return verdict, risk_score, confidence


def _run_qr(pipeline, ev):
    from analyzer.url_analyzer import analyze as url_analyze
    from parsers.url_extractor import normalize_url

    stored = ev.get("stored_path")
    pipeline.add_source("qr_analyzer")
    pipeline.engine_version = "qr_pipeline.v1"
    pipeline.stage("Input normalized", "done",
                   "Stored image located." if stored else "No stored image.")

    decoded = None  # None = could not decode / stack missing
    if stored and os.path.exists(stored):
        try:
            import io
            from PIL import Image as PILImage
            from pyzbar.pyzbar import decode as qr_decode
            with open(stored, "rb") as fh:
                raw = fh.read()
            img = PILImage.open(io.BytesIO(raw))
            img.load()
            results = qr_decode(img)
            decoded = [r.data.decode("utf-8", "replace") for r in results]
        except Exception:
            decoded = None

    if decoded is None:
        pipeline.stage("QR decoding", "unavailable",
                       "QR decoding library unavailable or image could not be decoded.")
        pipeline.payload = {
            "decoded": [],
            "note": "QR decoding library unavailable or image could not be decoded.",
        }
        return "UNAVAILABLE", 0, None

    pipeline.stage("QR decoding", "done",
                   "Decoded %d QR payload(s)." % len(decoded))

    urls = []
    for payload in decoded:
        p = payload.strip()
        if not p:
            continue
        if p.startswith(("http://", "https://")) or ("." in p and " " not in p):
            urls.append(normalize_url(p))
    pipeline.payload["decoded_raw"] = [p[:120] for p in decoded]

    if not urls:
        pipeline.stage("Risk calculation", "done",
                       "No URL destination present in QR payloads.")
        pipeline.payload["decoded"] = []
        pipeline.payload["note"] = "QR decoded but contained no URL destination."
        return "CLEAN", 0, None

    intel_configured = _vt_state()
    result = url_analyze(_url_analyzer_email(urls),
                         vt_lookup=(_vt_lookup_url if intel_configured else None))
    _indicators_to_findings(pipeline, result.get("indicators"), "qr_pipeline.url_analyzer")

    status = str(result.get("status") or "clean").upper()
    verdict = "MALICIOUS" if status == "MALICIOUS" else \
        ("SUSPICIOUS" if status == "SUSPICIOUS" else "CLEAN")
    risk_score = int(result.get("score", 0) or 0)
    pipeline.payload["decoded"] = (result.get("analyzed") or [])[:10]
    pipeline.payload["url_count"] = len(result.get("analyzed") or [])

    pipeline.stage("Risk calculation", "done",
                   "Decoded destination(s) scored via url_analyzer.")
    return verdict, risk_score, None


def _run_domain(pipeline, ev, domain_hint=None):
    from analyzer.url_analyzer import analyze as url_analyze
    from parsers.url_extractor import registrable_domain, \
        analyze_url_structure, normalize_url

    target = (domain_hint or (ev.get("content_text") or "")).strip()
    if "." not in target:
        raise AnalysisError("INVALID_DOMAIN",
                            "Evidence content is not a plausible domain.", 400)

    pipeline.add_source("domain_pipeline")
    pipeline.engine_version = "domain_pipeline.v1"
    pipeline.stage("Input normalized", "done", "Domain string extracted.")

    structure = analyze_url_structure(normalize_url("https://" + target))
    reg = registrable_domain(target.split("//")[-1].split("/")[0])

    # Real structural detail (plain-string findings from url_extractor).
    for f in (structure.get("findings") or [])[:6]:
        pipeline.findings.append({
            "finding_type": "domain_structure",
            "severity": "low",
            "title": "DOMAIN STRUCTURE",
            "detail": f,
            "source": "domain_pipeline.url_extractor",
        })

    intel_configured = _vt_state()
    result = url_analyze(_url_analyzer_email(["https://%s/" % target]),
                         vt_lookup=(_vt_lookup_url if intel_configured else None))
    _indicators_to_findings(pipeline, result.get("indicators"),
                            "domain_pipeline.url_analyzer")

    status = str(result.get("status") or "clean").upper()
    verdict = "MALICIOUS" if status == "MALICIOUS" else \
        ("SUSPICIOUS" if status == "SUSPICIOUS" else "CLEAN")
    risk_score = int(result.get("score", 0) or 0)

    analyzed = (result.get("analyzed") or [{}])[0] or {}
    intel = analyzed.get("reputation")
    pipeline.payload = {
        "domain": target,
        "registrable_domain": reg or structure.get("domain", ""),
        "hostname": structure.get("hostname", ""),
        "structure_findings": (structure.get("findings") or [])[:8],
        "url_intel_verdict": intel,
        "intel_available": analyzed.get("intel_available", False),
        "intel_note": analyzed.get("intel_note", ""),
        "url_result": analyzed,
    }

    if intel_configured:
        pipeline.stage("Threat intelligence", "done",
                       "Domain checked against VirusTotal.")
    else:
        pipeline.stage("Threat intelligence", "unavailable",
                       "VirusTotal not configured — structure analysis only.")

    net_host = (reg or structure.get("hostname") or target).split(
        "//")[-1].split("/")[0].split(":")[0].strip().lower()
    network = network_intel.lookup(net_host)
    pipeline.payload["network"] = network
    net_states = {network["dns"].get("state"),
                  network["rdap"].get("state")}
    if net_states == {"available"}:
        pipeline.stage("Network intelligence", "done",
                       "DNS + RDAP retrieved for %s." % net_host)
    elif net_states == {"invalid"}:
        pipeline.stage("Network intelligence", "unavailable",
                       "Not a plausible domain for DNS/RDAP.")
    else:
        pipeline.stage("Network intelligence", "unavailable",
                       "DNS/RDAP unreachable — structure analysis only.")

    pipeline.stage("Risk calculation", "done",
                   "Deterministic structural scoring (url_analyzer).")
    return verdict, risk_score, None


def _run_scam(pipeline, ev):
    from analyzer import scam_analyzer
    pipeline.add_source("scam_analyzer")
    pipeline.engine_version = "scam_analyzer.v1"
    pipeline.stage("Input normalized", "done", "Message content extracted.")
    result = scam_analyzer.analyze(_normalized_email(ev))
    pipeline.stage("Indicators extracted", "done",
                   "Detected %d indicator(s)." % len(result.get("indicators") or []))
    pipeline.stage("Risk calculation", "done", "Severity from detected signals.")
    pipeline.payload = result
    _indicators_to_findings(pipeline, result.get("indicators"), "scam_analyzer")
    return str(result.get("status") or "clean").upper(), \
        int(result.get("score", 0) or 0), None


def _run_sms(pipeline, ev):
    """SMS / smishing (AP): ML spam classification + scam-family signals.

    Never forced onto email-shaped models — the message text feeds the
    spam classifier and the scam-family detectors directly.
    """
    from analyzer import scam_analyzer, spam_analyzer
    predict, ml_ready = _ml_probe()
    pipeline.add_source("sms_pipeline.spam_analyzer")
    pipeline.add_source("sms_pipeline.scam_analyzer")
    pipeline.engine_version = "sms_pipeline.v1"
    pipeline.stage("Input normalized", "done", "Message text extracted.")

    text = _normalized_email(ev)
    if ml_ready:
        pipeline.stage("Local ML analysis", "done",
                       "Real model inference executed.")
        spam = spam_analyzer.analyze(text, predict)
    else:
        pipeline.stage("Local ML analysis", "unavailable",
                       "ML classifier unavailable in this environment.")
        spam = spam_analyzer.analyze(text, _stub_predict)

    scam = scam_analyzer.analyze(text)
    pipeline.stage("Scam signals", "done",
                   "Detected %d scam indicator(s)."
                   % len(scam.get("indicators") or []))

    spam_class = str(spam.get("classification") or "Unavailable")
    scam_status = str(scam.get("status") or "clean").lower()
    if spam_class == "Spam" or scam_status == "malicious":
        verdict = "MALICIOUS"
    elif scam_status == "suspicious":
        verdict = "SUSPICIOUS"
    elif spam_class == "Not Spam" and scam_status == "clean":
        verdict = "CLEAN"
    else:
        verdict = "UNAVAILABLE"

    pipeline.payload = {
        "spam_classification": spam_class,
        "spam_score": int(spam.get("score", 0) or 0),
        "spam_probability": float(spam.get("probability_spam", 0.0) or 0.0),
        "scam_status": scam_status,
        "scam_score": int(scam.get("score", 0) or 0),
        "scam_summary": scam.get("summary", ""),
        "ml_ready": bool(ml_ready),
    }
    _indicators_to_findings(pipeline, spam.get("indicators"),
                            "sms_pipeline.spam_analyzer")
    _indicators_to_findings(pipeline, scam.get("indicators"),
                            "sms_pipeline.scam_analyzer")
    pipeline.stage("Risk calculation", "done",
                   "Worst of spam/scam signals (deterministic).")
    confidence = float(spam.get("probability_spam", 0.0) or 0.0)
    return verdict, max(int(spam.get("score", 0) or 0),
                        int(scam.get("score", 0) or 0)), confidence


def _run_bec(pipeline, ev):
    from analyzer import bec_analyzer
    pipeline.add_source("bec_analyzer")
    pipeline.engine_version = "bec_analyzer.v1"
    pipeline.stage("Input normalized", "done", "Email identity + content extracted.")
    result = bec_analyzer.analyze(_normalized_email(ev))
    pipeline.stage("Indicators extracted", "done",
                   "Detected %d indicator(s)." % len(result.get("indicators") or []))
    pipeline.stage("Risk calculation", "done", "Severity from detected signals.")
    pipeline.payload = result
    _indicators_to_findings(pipeline, result.get("indicators"), "bec_analyzer")
    return str(result.get("status") or "clean").upper(), \
        int(result.get("score", 0) or 0), None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_target_urls(ev):
    """URLs and domains referenced in the evidence content (real extraction)."""
    from parsers.url_extractor import extract_urls_from_text
    text = ev.get("content_text") or ""
    urls = extract_urls_from_text(text, limit=60)
    if ev.get("evidence_type") in ("URL", "DOMAIN", "IP") and not urls:
        stripped = text.strip()
        if stripped:
            if "." in stripped:
                urls.append("https://" + stripped)
            else:
                urls.append(stripped)
    return urls


def _evidence_row(evidence_ref):
    if isinstance(evidence_ref, int) or str(evidence_ref).isdigit():
        row = db.query_one("SELECT * FROM evidence WHERE evidence_id = ?",
                           (int(evidence_ref),))
    else:
        row = db.query_one("SELECT * FROM evidence WHERE evidence_ref = ?",
                           (str(evidence_ref),))
    if not row:
        raise AnalysisError("EVIDENCE_NOT_FOUND",
                            "The requested evidence does not exist.", 404)
    return dict(row)


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------

def validate_analysis_type(analysis_type):
    if analysis_type not in ANALYSIS_REGISTRY:
        raise AnalysisError(
            "INVALID_ANALYSIS_TYPE",
            "analysis_type must be one of: %s." % ", ".join(ANALYSIS_TYPES), 400)


def compatible_evidence_types(analysis_type):
    validate_analysis_type(analysis_type)
    return ANALYSIS_REGISTRY[analysis_type]["evidence_types"]


def run_analysis(evidence_ref, analysis_type, actor=ACTOR_DEFAULT,
                 ip_address=None):
    """Run a real analysis over an evidence record and persist results."""
    validate_analysis_type(analysis_type)

    ev = _evidence_row(evidence_ref)
    ev_type = ev.get("evidence_type")
    allowed = ANALYSIS_REGISTRY[analysis_type]["evidence_types"]
    if ev_type not in allowed:
        raise AnalysisError(
            "INCOMPATIBLE_EVIDENCE",
            "Analysis type %s cannot run against %s evidence (requires %s)."
            % (analysis_type, ev_type, ", ".join(allowed)), 400)

    started = _now()
    pipeline = Pipeline()

    runners = {
        "EMAIL": _run_email, "PHISHING": _run_phishing, "SPAM": _run_spam,
        "URL": _run_url, "FILE": _run_file, "HASH": _run_hash,
        "QR": _run_qr, "DOMAIN": _run_domain, "SCAM": _run_scam,
        "BEC": _run_bec, "SMS": _run_sms,
    }
    runner = runners[analysis_type]
    verdict, risk_score, confidence = runner(pipeline, ev)

    completed = _now()
    # Section 40 — real start/end timestamps.
    payload_json_base = {
        "verdict": verdict, "started_at": started, "completed_at": completed,
        "stages": pipeline.stages, "findings": pipeline.findings,
        "analysis": pipeline.payload, "sources": pipeline.source,
        "engine_version": pipeline.engine_version,
    }

    # Honest status: a core local stage (ML / QR decode) being unavailable
    # makes the run partial. External threat intel being absent is reported
    # as a stage state, not a run failure — local analysis still completed.
    status = "COMPLETE"
    if verdict == "UNAVAILABLE":
        status = "PARTIAL"
    elif analysis_type in ("EMAIL", "SPAM") and any(
            s["name"] == "Local ML analysis" and s["status"] == "unavailable"
            for s in pipeline.stages):
        status = "PARTIAL"

    analysis_ref = _next_analysis_ref()
    payload_json = json.dumps(payload_json_base)

    with db.transaction():
        case_id = ev.get("case_id")
        db.execute(
            "INSERT INTO analyses(analysis_ref, case_id, evidence_id, "
            "analysis_type, status, verdict, risk_score, confidence, source, "
            "engine_version, payload_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (analysis_ref, case_id, ev["evidence_id"], analysis_type, status,
             verdict, risk_score, confidence,
             ", ".join(pipeline.source) or "local", pipeline.engine_version,
             payload_json, completed))

        analysis_id = db.query_one(
            "SELECT analysis_id FROM analyses WHERE analysis_ref = ?",
            (analysis_ref,))["analysis_id"]

        for f in pipeline.findings[:MAX_FINDINGS]:
            db.execute(
                "INSERT INTO analysis_findings(analysis_id, finding_type, "
                "severity, title, detail, evidence_ref, source) "
                "VALUES (?,?,?,?,?,?,?)",
                (analysis_id, f["finding_type"], f["severity"], f["title"],
                 f["detail"], ev["evidence_ref"], f["source"] or "local"))

        case_service.audit(
            "ANALYSIS_EXECUTED", "ANALYSIS_RUN", target_type="evidence",
            target_ref=ev["evidence_ref"],
            detail="%s analysis %s -> %s (score %s)"
                   % (analysis_type, analysis_ref, verdict, risk_score),
            actor=actor, ip_address=ip_address)

        if case_id:
            case_service.add_timeline_event(
                case_id, "analysis.completed",
                "%s analysis completed" % ANALYSIS_REGISTRY[analysis_type]["label"],
                detail="%s — verdict %s (risk score %s)"
                       % (analysis_ref, verdict, risk_score),
                actor=actor, source="Analysis Pipeline")

    return get_analysis(analysis_ref)


def get_analysis(analysis_ref):
    row = db.query_one("SELECT * FROM analyses WHERE analysis_ref = ?",
                       (str(analysis_ref),))
    if not row:
        row = db.query_one("SELECT * FROM analyses WHERE analysis_id = ?",
                           (int(analysis_ref),)) \
            if str(analysis_ref).isdigit() else None
    if not row:
        raise AnalysisError("ANALYSIS_NOT_FOUND",
                            "The requested analysis does not exist.", 404)

    data = dict(row)
    analysis_id = data["analysis_id"]

    evidence = db.query_one(
        "SELECT evidence_ref, evidence_type, title FROM evidence "
        "WHERE evidence_id = ?", (data["evidence_id"],))
    data["evidence"] = evidence
    case = db.query_one(
        "SELECT case_ref, title, status FROM cases WHERE case_id = ?",
        (data["case_id"],)) if data["case_id"] else None
    data["case"] = case

    data["findings"] = [dict(r) for r in db.query(
        "SELECT finding_type, severity, title, detail, evidence_ref, source "
        "FROM analysis_findings WHERE analysis_id = ? "
        "ORDER BY finding_id ASC", (analysis_id,))]

    try:
        data["payload"] = json.loads(data.get("payload_json") or "{}")
    except Exception:
        data["payload"] = {"parse_error": True}
    data.pop("payload_json", None)
    data.pop("analysis_id", None)
    data["type_info"] = ANALYSIS_REGISTRY.get(data.get("analysis_type"), {})
    return data


def list_analyses(case_ref=None, evidence_ref=None, analysis_type=None,
                  status=None, search=None, limit=50, offset=0):
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    where, params = ["1=1"], []
    if case_ref:
        where.append("c.case_ref = ?")
        params.append(str(case_ref))
    if evidence_ref:
        where.append("e.evidence_ref = ?")
        params.append(str(evidence_ref))
    if analysis_type:
        where.append("a.analysis_type = ?")
        params.append(str(analysis_type))
    if status:
        where.append("a.status = ?")
        params.append(str(status))
    if search:
        like = "%%%s%%" % str(search).strip()
        where.append("(a.analysis_ref LIKE ? OR a.verdict LIKE ? OR "
                     "e.evidence_ref LIKE ? OR a.payload_json LIKE ?)")
        params.extend([like, like, like, like])

    clause = " WHERE " + " AND ".join(where)

    total_row = db.query_one(
        "SELECT COUNT(*) AS n FROM analyses a "
        "LEFT JOIN evidence e ON e.evidence_id = a.evidence_id "
        "LEFT JOIN cases c ON c.case_id = a.case_id" + clause, tuple(params))
    total = total_row["n"] if total_row else 0

    rows = db.query(
        "SELECT a.analysis_ref, a.analysis_type, a.status, a.verdict, "
        "a.risk_score, a.confidence, a.engine_version, a.created_at, "
        "e.evidence_ref, e.evidence_type AS evidence_type, "
        "c.case_ref AS case_ref "
        "FROM analyses a "
        "LEFT JOIN evidence e ON e.evidence_id = a.evidence_id "
        "LEFT JOIN cases c ON c.case_id = a.case_id" + clause +
        " ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset))

    items = [dict(r) for r in rows]
    return {
        "items": items, "total": total,
        "limit": limit, "offset": offset,
        "has_more": (offset + len(rows)) < total,
    }