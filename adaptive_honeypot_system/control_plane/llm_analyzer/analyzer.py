from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dummy_llm_analyzer")

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200").rstrip("/")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "honeypot-logs-*")
ROUTING_CONTROLLER_URL = os.getenv("ROUTING_CONTROLLER_URL", "http://routing_controller:8001").rstrip("/")
ANALYZER_INTERVAL_SECONDS = float(os.getenv("ANALYZER_INTERVAL_SECONDS", "2"))
ANALYZER_WINDOW_SECONDS = int(os.getenv("ANALYZER_WINDOW_SECONDS", "300"))
ANALYZER_MAX_EVENTS = int(os.getenv("ANALYZER_MAX_EVENTS", "150"))
ANALYZER_APPLY_ROUTE = os.getenv("ANALYZER_APPLY_ROUTE", "true").strip().lower() in {"1", "true", "yes"}
ANALYZER_ENABLED = os.getenv("ANALYZER_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
EXPOSURE_MODE = os.getenv("EXPOSURE_MODE", "debug").strip().lower()
DEBUG_EXPOSURE_VALUES = {"debug", "dev", "development", "operator", "test"}
DEBUG_EXPOSURE = EXPOSURE_MODE in DEBUG_EXPOSURE_VALUES
ROUTE_COOLDOWN_SECONDS = float(os.getenv("ROUTE_COOLDOWN_SECONDS", "5"))
ANALYZER_STARTED_AT = datetime.now(timezone.utc)

STATE_DIM = 24

SQLI_RE = re.compile(
    r"('|\"|--|/\*|\*/|\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bexec\b|0x[0-9a-f]+|or\s+1\s*=\s*1)",
    re.IGNORECASE,
)
CMDI_RE = re.compile(
    r"(;|\||&&|\$\(|`|/etc/passwd|/etc/shadow|\bwhoami\b|\bid\b|\buname\b|\bcat\s|\bls\s|\bwget\s|\bcurl\s|\bnc\s|\bbash\b|\bsh\s)",
    re.IGNORECASE,
)
SSTI_RE = re.compile(r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\})", re.IGNORECASE | re.DOTALL)
SSRF_RE = re.compile(
    r"(169\.254\.169\.254|localhost|127\.0\.0\.|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.|file://|dict://|gopher://|/etc/|/proc/)",
    re.IGNORECASE,
)

ATTACK_TO_BACKEND = {
    "sqli": "sqli_api",
    "cmdi": "cmdi_api",
    "ssti": "ssti_api",
    "ssrf": "ssrf_api",
}

SERVICE_TO_ROUTE = {
    "real-backend": "normal_api",
    "sqli-honeypot": "sqli_api",
    "cmdi-honeypot": "cmdi_api",
    "ssti-honeypot": "ssti_api",
    "ssrf-honeypot": "ssrf_api",
}


class AnalyzeEventRequest(BaseModel):
    session_id: str = ""
    source_ip: str = ""
    path: str = "/"
    method: str = "POST"
    query: str = ""
    body_preview: str = ""
    service: str = "real-backend"
    status_code: int = 200
    apply_route: Optional[bool] = None


class AnalyzerStats(BaseModel):
    enabled: bool
    elasticsearch_url: str
    routing_controller_url: str
    seen_events: int
    decisions: int
    last_error: str = ""
    last_poll_at: str = ""


seen_event_ids: OrderedDict[str, float] = OrderedDict()
last_backend_by_key: dict[str, tuple[str, float]] = {}
stats = {
    "decisions": 0,
    "last_error": "",
    "last_poll_at": "",
}

app = FastAPI(
    title="Dummy LLM Analyzer",
    version="0.1.0",
    docs_url="/docs" if DEBUG_EXPOSURE else None,
    redoc_url="/redoc" if DEBUG_EXPOSURE else None,
    openapi_url="/openapi.json" if DEBUG_EXPOSURE else None,
)


def require_debug_exposure() -> None:
    if not DEBUG_EXPOSURE:
        raise HTTPException(status_code=404, detail="Not found")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def remember_seen(event_id: str) -> None:
    seen_event_ids[event_id] = time.time()
    while len(seen_event_ids) > 2000:
        seen_event_ids.popitem(last=False)


def detect_attack(text: str) -> Optional[str]:
    if SSTI_RE.search(text):
        return "ssti"
    if SSRF_RE.search(text):
        return "ssrf"
    if CMDI_RE.search(text):
        return "cmdi"
    if SQLI_RE.search(text):
        return "sqli"
    return None


def event_text(event: dict[str, Any]) -> str:
    fields = [
        event.get("method", ""),
        event.get("path", ""),
        event.get("query", ""),
        event.get("body_preview", ""),
        event.get("body", ""),
    ]
    return " ".join(str(value or "") for value in fields)


def build_state(event: dict[str, Any], attack: str) -> list[float]:
    subtype = {
        "sqli": [0.95, 0.02, 0.02, 0.01],
        "cmdi": [0.02, 0.95, 0.02, 0.01],
        "ssti": [0.02, 0.02, 0.95, 0.01],
        "ssrf": [0.02, 0.02, 0.01, 0.95],
    }[attack]
    current_route = 0.0 if event.get("service") == "real-backend" else 1.0
    status_code = int(event.get("status_code") or 200)
    failed_attempts = 0.65 if status_code >= 400 else 0.35
    payload_size = float(event.get("payload_size") or len(str(event.get("body_preview") or "")))
    content_anomaly = min(1.0, payload_size / 512.0)

    state = [
        1.0, 0.0, 0.0, 0.0,  # protocol=http
        0.25,                # session_age_norm, dummy memory window
        0.72,                # interaction_rate_norm
        failed_attempts,
        max(0.55, content_anomaly),
        0.40,                # probe_diversity_norm
        0.92, 0.0, 0.0, 0.0, # attack_category_onehot effective: injection
        *subtype,            # web_subtype_scores effective
        0.60,                # effective_evasion
        current_route,
        0.35,                # attack_vector_shift
        0.72,                # effective_historical_consistency
        0.50,                # effective_progression
        0.95,                # memory_decay_weight
        0.25,                # effective_shift_velocity
    ]
    if len(state) != STATE_DIM:
        raise RuntimeError(f"bad dummy state dimension: {len(state)}")
    return state


def route_key(event: dict[str, Any]) -> str:
    session_id = str(event.get("session_id") or "").strip()
    if session_id:
        return f"sid:{session_id}"
    source_ip = str(event.get("x_forwarded_for") or event.get("source_ip") or event.get("remote_addr") or "").split(",")[0].strip()
    return f"ip:{source_ip}" if source_ip else ""


def should_skip_repeated(key: str, backend: str) -> bool:
    previous = last_backend_by_key.get(key)
    now = time.time()
    if previous and previous[0] == backend and now - previous[1] < ROUTE_COOLDOWN_SECONDS:
        return True
    last_backend_by_key[key] = (backend, now)
    return False


def apply_decision(event: dict[str, Any], attack: str, apply_route: bool) -> dict[str, Any]:
    key = route_key(event)
    backend = ATTACK_TO_BACKEND[attack]
    if not key:
        return {"routed": False, "reason": "missing session_id/source_ip", "attack": attack, "backend": backend}
    if should_skip_repeated(key, backend):
        return {"routed": False, "reason": "cooldown", "attack": attack, "backend": backend, "key": key}

    session_id = str(event.get("session_id") or "").strip()
    source_ip = str(event.get("x_forwarded_for") or event.get("source_ip") or event.get("remote_addr") or "").split(",")[0].strip()
    state = build_state(event, attack)
    payload = {
        "protocol": "http",
        "session_id": session_id or None,
        "source_ip": source_ip or None,
        "state": state,
        "apply_route": apply_route,
    }
    response = requests.post(f"{ROUTING_CONTROLLER_URL}/decide", json=payload, timeout=5)
    response.raise_for_status()
    body = response.json()
    stats["decisions"] += 1

    decision_log = {
        "event_schema_version": "1.0",
        "event_type": "dummy_llm_decision",
        "ts": now_iso(),
        "service": "dummy-llm-analyzer",
        "session_id": session_id,
        "source_ip": source_ip,
        "detected_attack": attack,
        "target_backend": backend,
        "controller_response": body,
    }
    logger.info(json.dumps(decision_log, ensure_ascii=True))
    return {"routed": True, "attack": attack, "backend": backend, "controller_response": body}


def process_event(event: dict[str, Any], apply_route: Optional[bool] = None) -> dict[str, Any]:
    event_type = str(event.get("event_type") or "")
    service = str(event.get("service") or "")
    if event_type == "route_decision" or service == "routing-controller":
        return {"routed": False, "reason": "control-plane event"}
    if service and service not in SERVICE_TO_ROUTE:
        return {"routed": False, "reason": f"ignored service {service}"}
    if service and service != "real-backend":
        return {"routed": False, "reason": f"passive honeypot observation from {service}"}

    attack = detect_attack(event_text(event))
    if not attack:
        return {"routed": False, "reason": "no attack detected"}
    return apply_decision(event, attack, ANALYZER_APPLY_ROUTE if apply_route is None else apply_route)


def parse_source(hit: dict[str, Any]) -> Optional[dict[str, Any]]:
    source = hit.get("_source") or {}
    app_doc = source.get("app")
    if isinstance(app_doc, dict):
        return app_doc

    for candidate in (
        source.get("message"),
        (source.get("json") or {}).get("log") if isinstance(source.get("json"), dict) else None,
    ):
        if not candidate:
            continue
        text = str(candidate).strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def poll_elasticsearch_once() -> int:
    window_start = datetime.now(timezone.utc) - timedelta(seconds=ANALYZER_WINDOW_SECONDS)
    lower_bound = max(window_start, ANALYZER_STARTED_AT).isoformat()
    query = {
        "size": ANALYZER_MAX_EVENTS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": lower_bound}}},
    }
    response = requests.post(f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX}/_search", json=query, timeout=5)
    response.raise_for_status()
    hits = response.json().get("hits", {}).get("hits", [])

    processed = 0
    for hit in reversed(hits):
        event_id = str(hit.get("_id") or "")
        if not event_id or event_id in seen_event_ids:
            continue
        remember_seen(event_id)
        event = parse_source(hit)
        if not event:
            continue
        process_event(event)
        processed += 1

    return processed


def worker_loop() -> None:
    while True:
        if ANALYZER_ENABLED:
            try:
                processed = poll_elasticsearch_once()
                stats["last_error"] = ""
                stats["last_poll_at"] = now_iso()
                if processed:
                    logger.info("dummy analyzer processed %s events", processed)
            except Exception as exc:  # noqa: BLE001
                stats["last_error"] = str(exc)
                logger.warning("dummy analyzer poll failed: %s", exc)
        time.sleep(ANALYZER_INTERVAL_SECONDS)


@app.on_event("startup")
def startup() -> None:
    thread = threading.Thread(target=worker_loop, name="dummy-analyzer-worker", daemon=True)
    thread.start()


@app.get("/health")
def health() -> dict[str, Any]:
    if not DEBUG_EXPOSURE:
        return {"status": "ok"}

    return AnalyzerStats(
        enabled=ANALYZER_ENABLED,
        elasticsearch_url=ELASTICSEARCH_URL,
        routing_controller_url=ROUTING_CONTROLLER_URL,
        seen_events=len(seen_event_ids),
        decisions=int(stats["decisions"]),
        last_error=str(stats["last_error"]),
        last_poll_at=str(stats["last_poll_at"]),
    ).model_dump()


@app.post("/analyze")
def analyze(event: AnalyzeEventRequest) -> dict[str, Any]:
    require_debug_exposure()
    return process_event(event.model_dump(), apply_route=event.apply_route)
