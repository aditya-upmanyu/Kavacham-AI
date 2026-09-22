"""
parsers/email_parser.py
=======================
Converts a raw Gmail API message into one predictable `NormalizedEmail`
object consumed by every analyzer in the unified engine.

The Gmail API (format=full) payload structure:

    {
      "id": "...",
      "threadId": "...",
      "snippet": "...",
      "payload": {
        "headers": [{"name": ..., "value": ...}, ...],
        "mimeType": "...",
        "parts": [... nested MIME parts ...],
        "body": {"data": "<base64url>"} | {"attachmentId": ..., "size": ...}
      }
    }

No external libraries beyond stdlib + beautifulsoup4 are required.
Attachment pixel/binary data is only decoded when requested (bounded size)
so we never pull heavy contents into memory by default.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import base64
import re
import hashlib
import email.utils

from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class EmailAttachment:
    """Metadata for an email attachment (content deliberately NOT stored)."""
    filename: str = ""
    mime_type: str = ""
    size: int = 0
    sha256: str = ""
    extension: str = ""
    attachment_id: str = ""
    part_index: int = 0

    def risk_summary(self) -> Dict:
        return {
            "filename": self.filename,
            "mime_type": self.mime_type,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
        }


@dataclass
class NormalizedEmail:
    """Single predictable email object consumed by every analyzer."""

    id: str = ""
    thread_id: str = ""
    snippet: str = ""

    sender_raw: str = ""
    sender_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""

    reply_to_raw: str = ""
    reply_to_email: str = ""
    reply_to_domain: str = ""

    return_path: str = ""
    recipients: List[str] = field(default_factory=list)

    subject: str = ""
    date: str = ""

    body_text: str = ""
    body_html: str = ""

    headers: Dict[str, str] = field(default_factory=dict)  # lowercase name -> value

    urls: List[str] = field(default_factory=list)          # normalized, deduped
    anchor_map: List[Dict] = field(default_factory=list)   # {href, text} pairs
    attachments: List[EmailAttachment] = field(default_factory=list)
    qr_codes: List[Dict] = field(default_factory=list)     # {source, url} decoded QRs

    has_html: bool = False
    raw: dict = field(default_factory=dict, repr=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decode_base64url(data_str: str) -> str:
    if not data_str:
        return ""
    try:
        missing_padding = len(data_str) % 4
        if missing_padding:
            data_str += "=" * (4 - missing_padding)
        raw = base64.urlsafe_b64decode(data_str)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_base64url_bytes(data_str: str) -> bytes:
    if not data_str:
        return b""
    try:
        missing_padding = len(data_str) % 4
        if missing_padding:
            data_str += "=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(data_str)
    except Exception:
        return b""


def parse_address(raw_address: str) -> tuple:
    """Parse an RFC-2822 address into (display_name, email, domain)."""
    if not raw_address or not raw_address.strip():
        return ("", "", "")
    try:
        name, addr = email.utils.parseaddr(raw_address)
    except Exception:
        name, addr = "", raw_address
    name = (name or "").strip().strip('"')
    addr = (addr or raw_address).strip()
    domain = ""
    if "@" in addr:
        domain = addr.rsplit("@", 1)[1].lower()
    return (name, addr, domain)


_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)

TEXT_AHEAD_LIMIT = 120000  # cap decoded body size used for extraction


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _collect_headers(payload: dict) -> Dict[str, str]:
    headers = {}
    for h in payload.get("headers", []):
        name = (h.get("name", "") or "").lower()
        value = (h.get("value", "") or "").strip()
        if name:
            headers[name] = value
    return headers


def _collect_body(payload: dict) -> tuple:
    """Returns (body_text, body_html, num_links, has_html)."""
    plain_parts: List[str] = []
    html_parts: List[str] = []
    html_raw_parts: List[str] = []
    num_links = 0
    has_html = False

    def walk(part):
        nonlocal num_links, has_html
        mime = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data", "")
        if mime == "text/plain" and body_data:
            decoded = decode_base64url(body_data)
            if decoded.strip():
                plain_parts.append(decoded)
                num_links += len(_URL_RE.findall(decoded[:TEXT_AHEAD_LIMIT]))
        elif mime == "text/html" and body_data:
            has_html = True
            decoded = decode_base64url(body_data)
            if decoded.strip():
                html_raw_parts.append(decoded)
                try:
                    soup = BeautifulSoup(decoded, "html.parser")
                    num_links += len(soup.find_all("a"))
                    for el in soup(["script", "style", "noscript"]):
                        el.extract()
                    cleaned = soup.get_text(separator=" ", strip=True)
                    if cleaned:
                        html_parts.append(cleaned)
                except Exception:
                    html_parts.append(decoded)
        for subpart in part.get("parts", []):
            walk(subpart)

    walk(payload)

    body_text = " ".join(plain_parts).strip()
    if not body_text:
        body_text = " ".join(html_parts).strip()
    body_html = ("\n".join(html_raw_parts)).strip()
    return (body_text, body_html, num_links, has_html)


def _collect_anchors(payload: dict) -> List[Dict]:
    """Extract {href, text} pairs from all HTML parts."""
    anchors: List[Dict] = []
    seen = set()

    def walk(part):
        mime = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data", "")
        if mime == "text/html" and body_data:
            try:
                soup = BeautifulSoup(decode_base64url(body_data), "html.parser")
                for a in soup.find_all("a", href=True)[:60]:
                    href = a["href"].strip()
                    text = a.get_text(" ", strip=True).strip()[:120]
                    key = (href, text)
                    if key not in seen:
                        seen.add(key)
                        anchors.append({"href": href, "text": text or href})
            except Exception:
                pass
        for subpart in part.get("parts", []):
            walk(subpart)

    walk(payload)
    return anchors


def _extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    return [u.rstrip(".,;:!?)]}>'\"") for u in _URL_RE.findall(text[:TEXT_AHEAD_LIMIT])]


def _collect_attachments(payload: dict, max_parts: int = 30) -> List[EmailAttachment]:
    """Walk MIME parts and return attachment metadata (content not loaded)."""
    attachments: List[EmailAttachment] = []
    part_index = 0

    def walk(part):
        nonlocal part_index
        filename = (part.get("filename") or "").strip()
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        size = int(body.get("size", 0) or 0)

        # All non-multipart, non-inline-display parts carrying data are attachments
        is_attachment = bool(filename) or (
            body.get("attachmentId") and part.get("disposition") == "attachment"
        )
        if is_attachment and len(attachments) < max_parts:
            ext = ""
            if "." in filename:
                ext = "." + filename.rsplit(".", 1)[1].lower()
            att = EmailAttachment(
                filename=filename or "attachment",
                mime_type=mime,
                size=size,
                extension=ext,
                attachment_id=body.get("attachmentId", ""),
                part_index=part_index,
            )
            # Compute SHA-256 hash from bounded binary data when available
            data_str = body.get("data", "")
            if data_str:
                raw = decode_base64url_bytes(data_str)
                if raw:
                    att.size = len(raw)
                    att.sha256 = hashlib.sha256(raw).hexdigest()
            attachments.append(att)
        part_index += 1

        for subpart in part.get("parts", []):
            walk(subpart)

    walk(payload)
    return attachments


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def normalize_gmail_message(msg_data: dict) -> NormalizedEmail:
    """
    Convert a raw Gmail `messages.get(format=full)` response into a
    NormalizedEmail. Designed to fail softly — never raise.
    """
    payload = msg_data.get("payload", {}) or {}
    headers = _collect_headers(payload)
    body_text, body_html, num_links, has_html = _collect_body(payload)

    sender_raw = headers.get("from", "") or "Unknown Sender"
    sender_name, sender_email, sender_domain = parse_address(sender_raw)

    reply_to_raw = headers.get("reply-to", "") or ""
    _, reply_to_email, reply_to_domain = parse_address(reply_to_raw)

    return_path = headers.get("return-path", "") or ""
    recipients = [addr for addr in headers.get("to", "").split(",") if addr.strip()]

    urls = _extract_urls_from_text(body_text)
    anchors = _collect_anchors(payload)
    for a in anchors:
        href = a["href"].strip()
        if href.startswith(("http://", "https://")):
            urls.append(href)
    # Deduplicate preserving order
    seen, deduped = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    attachments = _collect_attachments(payload)

    snippet = msg_data.get("snippet", "") or ""
    if not body_text and snippet:
        body_text = snippet

    return NormalizedEmail(
        id=msg_data.get("id", ""),
        thread_id=msg_data.get("threadId", ""),
        snippet=snippet,
        sender_raw=sender_raw,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_raw=reply_to_raw,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        recipients=recipients,
        subject=headers.get("subject", "(No Subject)"),
        date=headers.get("date", "Unknown Date"),
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        urls=deduped,
        anchor_map=anchors,
        attachments=attachments,
        has_html=has_html,
        raw=msg_data,
    )


# ---------------------------------------------------------------------------
# Manual phishing-checker entrypoint (raw fields, no Gmail API involved)
# ---------------------------------------------------------------------------

_TRUE_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def build_normalized_email(
    sender: str = "",
    subject: str = "",
    body: str = "",
    urls: str = "",
    reply_to: str = "",
    return_path: str = "",
    date: str = "",
    recipients: str = "",
) -> NormalizedEmail:
    """
    Build a NormalizedEmail from raw user-typed fields (Phishing Checker).

    Only trusts data typed by the user. Sender addresses are parsed with the
    same RFC helpers as Gmail messages; URLs are extracted from the body AND
    the optional "URL / Advanced Indicators" field (scheme-less hosts are
    normalized to https:// so the structural analyzer can inspect them).

    Swallows all errors and always returns a usable NormalizedEmail.
    """
    sender_raw = (sender or "").strip() or "Unknown Sender"
    sender_name, sender_email, sender_domain = parse_address(sender_raw)

    reply_to_raw = (reply_to or "").strip()
    _, reply_to_email, reply_to_domain = parse_address(reply_to_raw)

    subject_txt = (subject or "").strip() or "(No Subject)"
    body_txt = (body or "").strip()
    url_field = (urls or "").strip()

    urls_found: List[str] = []

    # 1) URLs naturally present in the message body
    urls_found.extend(_extract_urls_from_text(body_txt))

    # 2) Explicitly typed URLs / domains (separated by whitespace, commas, newlines)
    for part in re.split(r"[\s,;]+", url_field):
        p = part.strip()
        if not p:
            continue
        p = p.rstrip(".,;:!?)]}>'\"")
        if p.startswith("www.") and not _TRUE_SCHEME_RE.match(p):
            p = "https://" + p
        if "." in p and " " not in p and not _TRUE_SCHEME_RE.match(p):
            p = "https://" + p
        urls_found.append(p)

    # Deduplicate preserving order
    seen, deduped = set(), []
    for u in urls_found:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    headers: Dict[str, str] = {"subject": subject_txt}
    if sender_raw and sender_raw != "Unknown Sender":
        headers["from"] = sender_raw
    if reply_to_raw:
        headers["reply-to"] = reply_to_raw
    if return_path.strip():
        headers["return-path"] = return_path.strip()
    if recipients.strip():
        headers["to"] = recipients.strip()
    if date.strip():
        headers["date"] = date.strip()

    return NormalizedEmail(
        id="manual-phishing-check",
        sender_raw=sender_raw,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_raw=reply_to_raw,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        return_path=return_path.strip(),
        recipients=[r.strip() for r in recipients.split(",") if r.strip()],
        subject=subject_txt,
        date=date.strip() or "Unknown Date",
        body_text=body_txt,
        headers=headers,
        urls=deduped,
        anchor_map=[{"href": u, "text": u} for u in deduped],
        attachments=[],
    )