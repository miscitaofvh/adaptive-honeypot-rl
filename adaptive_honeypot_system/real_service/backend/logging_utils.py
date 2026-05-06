import json
import logging
import logging.handlers
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import g, request


SENSITIVE_KEYS = {"password", "token", "access_token", "authorization", "secret"}
MAX_BODY_PREVIEW = 2048
FILEBEAT_HOST = os.environ.get("FILEBEAT_HOST", "filebeat")
FILEBEAT_SERVICE_PORT = int(os.environ.get("FILEBEAT_SERVICE_PORT", "5141"))


def _logger() -> logging.Logger:
    logger = logging.getLogger("real_service")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=(FILEBEAT_HOST, FILEBEAT_SERVICE_PORT),
                socktype=socket.SOCK_DGRAM,
            )
            syslog_handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(syslog_handler)
        except Exception:
            pass
    logger.propagate = False
    return logger


def _mask_value(key: str, value: Any) -> Any:
    if key.lower() in SENSITIVE_KEYS:
        return "[redacted]"
    if isinstance(value, dict):
        return {k: _mask_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(key, item) for item in value]
    return value


def _body_preview() -> tuple[str, int]:
    try:
        raw = request.get_data(cache=True) or b""
        payload_size = len(raw)

        if request.is_json:
            data = request.get_json(silent=True)
            if isinstance(data, dict):
                data = {k: _mask_value(str(k), v) for k, v in data.items()}
            preview = json.dumps(data, ensure_ascii=True)
        else:
            preview = raw[:MAX_BODY_PREVIEW].decode("utf-8", errors="replace")

        return preview[:MAX_BODY_PREVIEW], payload_size
    except Exception:
        return "", 0


def install_request_logging(app) -> None:
    @app.before_request
    def _before_request() -> None:
        g.start_time = time.monotonic()
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex

    @app.after_request
    def _after_request(response):
        duration_ms = round((time.monotonic() - getattr(g, "start_time", time.monotonic())) * 1000, 2)
        body_preview, payload_size = _body_preview()

        record = {
            "event_schema_version": "1.0",
            "event_type": "request",
            "ts": int(datetime.now(timezone.utc).timestamp()),
            "service": app.config.get("SERVICE_NAME", "real-backend"),
            "request_id": getattr(g, "request_id", ""),
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", errors="replace"),
            "remote_addr": request.remote_addr,
            "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
            "session_id": request.cookies.get("sid", ""),
            "user_agent": request.headers.get("User-Agent", ""),
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "payload_size": payload_size,
            "body_preview": body_preview,
            "route_hint": request.headers.get("X-Forwarded-Service", ""),
        }

        response.headers["X-Request-ID"] = record["request_id"]
        _logger().info(json.dumps(record, ensure_ascii=True))
        return response
