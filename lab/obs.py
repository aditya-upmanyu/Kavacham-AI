"""KAVACHAM LAB — observability (Sections BO/BZ).

Every Lab HTTP request gets a correlation/request id:

    frontend (X-Correlation-ID, optional)
      -> API (X-Request-ID response header, also inbound id when sent)
      -> service layer (obs.request_id())
      -> structured log line (request_id / service / operation / status /
         duration_ms)

Never log secrets: only the method + path are recorded, never the query
string, headers or request/response bodies. Only stdlib (logging, json,
time, uuid) — no new dependencies.
"""

import json
import logging
import time
import uuid

from flask import g, request

SERVICE_NAME = "lab"
LOG_NAME = "kavacham.obs"
_CORR_HEADER = "X-Correlation-ID"
_RESP_HEADER = "X-Request-ID"

_LOGGER = logging.getLogger(LOG_NAME)

if not _LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(_handler)
_LOGGER.setLevel(logging.INFO)
_LOGGER.propagate = False


def init_blueprint(bp):
    """Register request hooks on the Lab blueprint (call once, at import)."""

    @bp.before_request
    def _assign_request_id():
        g.request_id = (
            request.headers.get(_CORR_HEADER) or uuid.uuid4().hex[:12]
        )
        g.request_start = time.perf_counter()

    @bp.after_request
    def _observe_request(response):
        rid = getattr(g, "request_id", None) or uuid.uuid4().hex[:12]
        started = getattr(g, "request_start", None)
        duration = (
            round((time.perf_counter() - started) * 1000.0, 2)
            if started is not None
            else None
        )
        response.headers.set(_RESP_HEADER, rid)
        from lab import ratelimit as _rl
        for _k, _v in _rl.SECURE_HEADERS.items():
            response.headers.setdefault(_k, _v)
        _LOGGER.info(
            json.dumps(
                {
                    "request_id": rid,
                    "service": SERVICE_NAME,
                    "operation": "%s %s" % (request.method, request.path),
                    "duration_ms": duration,
                    "status": response.status_code,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return response


def request_id():
    """Return the current Lab request id (None outside a request)."""
    try:
        return g.get("request_id")
    except Exception:
        return None
