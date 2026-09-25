"""KAVACHAM LAB — rate limiting + secure response headers (Section BS).

Rate limiting is an in-memory per-IP token bucket (stdlib only, no new
dependencies). It gates expensive or mutating Lab endpoints; over-limit
callers get a Section 49 RATE_LIMITED 429 with Retry-After. Buckets are
process-local by design — documented, not hidden.

Secure headers ride on every Lab response via obs (nosniff, DENY
framing, no-referrer, locked-down permissions). No Content-Security-
Policy is emitted: Lab pages use inline style attributes throughout,
so a script-src/style-src policy would either break the UI or require
'unsafe-inline' (theater). That trade-off is documented here instead
of faked (BT review).
"""

import time

# Default budget: 120 requests per 60s window per IP per scope.
LIMIT = 120
WINDOW_S = 60

_buckets = {}


def _now():
    return time.monotonic()


def check(ip, scope):
    """Consume one token. Returns (allowed, remaining, retry_after)."""
    now = _now()
    key = (ip or "unknown", scope or "default")
    tokens, stamp = _buckets.get(key, (float(LIMIT), now))
    elapsed = max(0.0, now - stamp)
    tokens = min(float(LIMIT), tokens + elapsed * (LIMIT / WINDOW_S))
    if tokens < 1.0:
        retry_after = max(1, int((1.0 - tokens) * (WINDOW_S / LIMIT)) + 1)
        _buckets[key] = (tokens, now)
        return False, 0, retry_after
    tokens -= 1.0
    _buckets[key] = (tokens, now)
    return True, int(tokens), 0


def reset():
    """Clear all buckets (tests + operator reset)."""
    _buckets.clear()


SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
