"""
analyzer/sender_analyzer.py
===========================
Sender identity / spoofing engine.

Compares the display name, From address, Reply-To and Return-Path to catch
impersonation and domain mismatches. Evidence-based: a Gmail address alone is
never treated as malicious.
"""

import re
from . import build_result, sum_indicators, severity_from_score, status_from_score

# Impersonation-watch list: claimed organization -> keywords + official domains.
BRAND_MAP = {
    "microsoft": {"keywords": ("microsoft",), "domains": ("microsoft.com", "outlook.com")},
    "google": {"keywords": ("google", "gmail"), "domains": ("google.com", "gmail.com")},
    "paypal": {"keywords": ("paypal",), "domains": ("paypal.com", "paypal-mktg.com")},
    "amazon": {"keywords": ("amazon",), "domains": ("amazon.com", "amazon.in", "amazon.co.uk")},
    "apple": {"keywords": ("apple", "icloud"), "domains": ("apple.com", "icloud.com")},
    "netflix": {"keywords": ("netflix",), "domains": ("netflix.com",)},
    "linkedin": {"keywords": ("linkedin",), "domains": ("linkedin.com",)},
    "facebook": {"keywords": ("facebook",), "domains": ("facebook.com", "fb.com", "meta.com")},
    "whatsapp": {"keywords": ("whatsapp",), "domains": ("whatsapp.com",)},
    "github": {"keywords": ("github",), "domains": ("github.com",)},
    "dropbox": {"keywords": ("dropbox",), "domains": ("dropbox.com",)},
    "verizon": {"keywords": ("verizon",), "domains": ("verizon.com",)},
    "sbi": {"keywords": ("sbi", "state bank"), "domains": ("sbi.co.in", "onlinesbi.sbi")},
    "hdfc": {"keywords": ("hdfc",), "domains": ("hdfcbank.com",)},
    "icici": {"keywords": ("icici",), "domains": ("icicibank.com",)},
    "axis": {"keywords": ("axis bank",), "domains": ("axisbank.com",)},
}

SUSPICIOUS_LOCALPARTS = ("no-reply", "noreply", "support", "admin", "service",
                         "secure", "verify", "alert", "update", "helpdesk",
                         "security", "account")


def _looks_like_brand(display_name: str) -> str | None:
    """Return brand key if the display name claims to be a known org."""
    dn = (display_name or "").lower()
    for brand, spec in BRAND_MAP.items():
        for kw in spec["keywords"]:
            if kw in dn:
                return brand
    return None


def analyze(email):
    """Analyze sender identity / spoofing signals."""
    indicators = []
    domain = (email.sender_domain or "").lower()
    display = email.sender_name or email.sender_raw.split("<")[0].strip() or ""
    reply_domain = (email.reply_to_domain or "").lower()
    return_path = (email.return_path or "").lower().strip("<>")

    # 1. Brand impersonation — display name claims an org the domain doesn't own
    claimed_brand = _looks_like_brand(display)
    if claimed_brand:
        official = BRAND_MAP[claimed_brand]["domains"]
        if domain and domain not in official and not _is_free_mail(domain):
            indicators.append({
                "type": "brand_impersonation",
                "evidence": (
                    f"Display name '{display}' suggests {claimed_brand.upper()}, "
                    f"but the sender address uses '{email.sender_email or 'unknown'}' "
                    f"from unrelated domain '{domain}'."
                ),
                "severity": "high", "category": "sender",
            })
        elif domain and domain not in official and _is_free_mail(domain):
            indicators.append({
                "type": "brand_free_mail_mismatch",
                "evidence": (
                    f"Display name '{display}' claims to be {claimed_brand.upper()} "
                    f"but the message came from a personal/free-mail domain '{domain}'."
                ),
                "severity": "medium", "category": "sender",
            })

    # 2. Reply-To domain mismatch (classic redirect/reply spoofing)
    if domain and reply_domain and reply_domain != domain:
        indicators.append({
            "type": "reply_to_mismatch",
            "evidence": (
                f"Reply-To domain '{reply_domain}' differs from sender domain '{domain}'. "
                "Replies could be routed to an unrelated party."
            ),
            "severity": "high", "category": "sender",
        })

    # 3. Return-Path mismatch (envelope vs header)
    rp_domain = ""
    if "@" in return_path:
        rp_domain = return_path.rsplit("@", 1)[1]
    if rp_domain and domain and rp_domain != domain and rp_domain not in (domain,):
        indicators.append({
            "type": "return_path_mismatch",
            "evidence": f"Return-Path '{return_path}' does not match the From domain '{domain}'.",
            "severity": "medium", "category": "sender",
        })

    # 4. Fully-qualified-looking local part of From (display "Support" but it's fine)
    local = (email.sender_email or "").split("@")[0].lower() if email.sender_email else ""
    if local and any(s in local for s in SUSPICIOUS_LOCALPARTS) and domain and _is_free_mail(domain):
        indicators.append({
            "type": "service_localpart_free_mail",
            "evidence": (
                f"Sender '{email.sender_email}' uses a service-style local part "
                f"('{local}') on a public mail domain."
            ),
            "severity": "low", "category": "sender",
        })

    # 5. Numeric-heavy / lookalike domain (141414..., micr0soft, paypa1)
    if domain:
        lookalike = re.findall(r"(micr0soft|paypa1|amaz0n|0ffice|11nkedin|goog1e)", domain.lower())
        if lookalike:
            indicators.append({
                "type": "lookalike_domain",
                "evidence": f"Domain '{domain}' uses character substitution of a well-known brand ({lookalike[0]}).",
                "severity": "high", "category": "sender",
            })

    score = sum_indicators([i["severity"] for i in indicators])
    if not indicators:
        summary = "Sender identity shows no spoofing indicators."
    else:
        summary = f"Sender identity review found {len(indicators)} suspicious signal(s)."
    status = "malicious" if score >= 50 else ("suspicious" if score >= 20 else "clean")

    return build_result(status, severity_from_score(score), score, indicators, summary,
                        sender_email=email.sender_email,
                        sender_domain=domain,
                        display_name=display,
                        reply_to_email=email.reply_to_email,
                        return_path=return_path)


def _is_free_mail(domain: str) -> bool:
    return domain in {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
        "protonmail.com", "icloud.com", "zoho.com", "gmx.com", "yandex.com",
        "live.com", "mail.com", "gmx.us",
    }