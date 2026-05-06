from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    from groq import Groq
except ImportError:  # pragma: no cover - local fallback when optional provider is absent
    Groq = None  # type: ignore[assignment]

CONTROL_PLANE_DIR = Path(__file__).resolve().parents[1]
if str(CONTROL_PLANE_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE_DIR))

from state_builder import STATE_DIM, STATE_SCHEMA_VERSION, StateVector  # noqa: E402


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("llm_analyzer")

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200").rstrip("/")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "honeypot-logs-*")
ROUTING_CONTROLLER_URL = os.getenv("ROUTING_CONTROLLER_URL", "http://routing_controller:8001").rstrip("/")
ANALYZER_INTERVAL_SECONDS = float(os.getenv("ANALYZER_INTERVAL_SECONDS", "5"))
ANALYZER_WINDOW_SECONDS = int(os.getenv("ANALYZER_WINDOW_SECONDS", "300"))
ANALYZER_MAX_EVENTS = int(os.getenv("ANALYZER_MAX_EVENTS", "150"))
ANALYZER_APPLY_ROUTE = os.getenv("ANALYZER_APPLY_ROUTE", "true").strip().lower() in {"1", "true", "yes"}
ANALYZER_ENABLED = os.getenv("ANALYZER_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
EXPOSURE_MODE = os.getenv("EXPOSURE_MODE", "debug").strip().lower()
DEBUG_EXPOSURE = EXPOSURE_MODE in {"debug", "dev", "development", "operator", "test"}
ROUTE_COOLDOWN_SECONDS = float(os.getenv("ROUTE_COOLDOWN_SECONDS", "5"))
ANALYZER_ROUTE_THRESHOLD = float(os.getenv("ANALYZER_ROUTE_THRESHOLD", "0.45"))
SERVICE_BODY_CACHE_SECONDS = float(os.getenv("SERVICE_BODY_CACHE_SECONDS", "120"))
ANALYZER_STARTED_AT = datetime.now(timezone.utc)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "15"))

_groq_client: Optional[Groq] = None
if GROQ_API_KEY and Groq is not None:
    _groq_client = Groq(api_key=GROQ_API_KEY)
elif GROQ_API_KEY and Groq is None:
    logger.warning("groq package not installed — LLM calls will use rule fallback")
else:
    logger.warning("GROQ_API_KEY not set — LLM calls will be skipped (graceful degradation)")

# Honeypot backends exposed in HAProxy
ATTACK_TO_BACKEND = {
    "sqli": "sqli_api",
    "cmdi": "cmdi_api",
    "ssti": "ssti_api",
    "ssrf": "ssrf_api",
}

# Paths that are only reachable via API — frontend/static hits are ignored
API_PATH_PREFIX = "/api/"

# Fields to drop from every event before sending to LLM (always-constant or infra noise)
_DROP_FIELDS = frozenset({
    "event_type",   # always "gateway_request"
    "service",      # always "haproxy"
    "frontend",     # always "web_in"
    "http_version", # always "HTTP/1.1"
    "active_conn",  # system load, not attack signal
    "ts",           # unix epoch duplicate of @timestamp
    "x_forwarded_for",  # always "-" in direct Docker bridge
    "server",       # internal upstream name, not useful for LLM
})

# HAProxy emits "-" for absent/empty header captures — treat as null
_HAPROXY_NULL = {"-", ""}


# ---------------------------------------------------------------------------
# Session memory (in-process; Redis is out of scope for this milestone)
# ---------------------------------------------------------------------------

# session_id → last updated_memory_context string from LLM
_session_memory: dict[str, str] = {}
# session_id → timestamp of first seen event (for session_age calculation)
_session_first_seen: dict[str, float] = {}
# session_id → (backend, timestamp) for cooldown dedup
_last_route_by_session: dict[str, tuple[str, float]] = {}
_session_last_attack: dict[str, str] = {}

seen_event_ids: OrderedDict[str, float] = OrderedDict()
# session_id → list of clean event dicts accumulated since last analysis cycle
_pending_events: dict[str, list[dict]] = defaultdict(list)
# (session_id, method, path) → (body_preview, timestamp), used when Filebeat
# ingests service logs and gateway logs in different polling windows.
_recent_service_bodies: dict[tuple[str, str, str], tuple[str, float]] = {}

stats: dict[str, Any] = {
    "decisions": 0,
    "last_error": "",
    "last_poll_at": "",
    "llm_calls": 0,
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AnalyzerStats(BaseModel):
    enabled: bool
    state_schema: str
    state_dim: int
    elasticsearch_url: str
    routing_controller_url: str
    seen_events: int
    decisions: int
    llm_calls: int
    last_error: str = ""
    last_poll_at: str = ""


app = FastAPI(
    title="LLM Analyzer",
    version="0.2.0",
    docs_url="/docs" if DEBUG_EXPOSURE else None,
    redoc_url="/redoc" if DEBUG_EXPOSURE else None,
    openapi_url="/openapi.json" if DEBUG_EXPOSURE else None,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def require_debug_exposure() -> None:
    if not DEBUG_EXPOSURE:
        raise HTTPException(status_code=404, detail="Not found")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def remember_seen(event_id: str) -> None:
    seen_event_ids[event_id] = time.time()
    while len(seen_event_ids) > 2000:
        seen_event_ids.popitem(last=False)


def _nullify(value: Any) -> Any:
    """Convert HAProxy absent-header sentinel '-' to None."""
    if isinstance(value, str) and value in _HAPROXY_NULL:
        return None
    return value


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _events_text(events: list[dict]) -> str:
    parts: list[str] = []
    for event in events:
        for key in ("method", "path", "query", "request_body", "user_agent", "referer", "content_type"):
            value = event.get(key)
            if value is not None:
                parts.append(str(value))
    return "\n".join(parts).lower()


def _score_patterns(text: str, patterns: tuple[str, ...]) -> float:
    hits = sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))
    if hits == 0:
        return 0.0
    return min(0.95, 0.55 + hits * 0.15)


def rule_based_semantic_fallback(session_id: str, events: list[dict]) -> dict[str, Any]:
    """Produce LLM-shaped semantic output when the provider is unavailable."""
    text = _events_text(events)
    sqli = _score_patterns(text, (
        r"\bunion\b\s+\bselect\b",
        r"\bselect\b.+\bfrom\b",
        r"\bor\b\s+1\s*=\s*1",
        r"--|#|/\*|\*/",
        r"\binformation_schema\b|\bdrop\b|\binsert\b|\bupdate\b",
    ))
    cmdi = _score_patterns(text, (
        r";|\||&&|`|\$\(",
        r"\bwhoami\b|\bid\b|\buname\b|\bcat\b|\bls\b|\bcurl\b|\bwget\b",
        r"/etc/passwd|/etc/shadow|cmd\.exe|powershell",
    ))
    ssti = _score_patterns(text, (
        r"\{\{|\}\}|\{%|%\}",
        r"__class__|__mro__|__subclasses__|config|jinja",
        r"\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}",
    ))
    ssrf = _score_patterns(text, (
        r"169\.254\.169\.254|metadata\.google|metadata\.aws",
        r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]",
        r"file://|gopher://|dict://|ftp://",
        r"/latest/meta-data|internal|admin",
    ))

    scores = [sqli, cmdi, ssti, ssrf]
    best_score = max(scores)
    previous_attack = _session_last_attack.get(session_id)
    subtypes = ["sqli", "cmdi", "ssti", "ssrf"]
    best_attack = subtypes[scores.index(best_score)] if best_score > 0 else "benign"

    encoded_or_obfuscated = _score_patterns(text, (
        r"%[0-9a-f]{2}",
        r"\\x[0-9a-f]{2}",
        r"base64|fromcharcode|char\(",
        r"\.\./|\.\.\\",
    ))
    request_count = max(1, len(events))
    failed_count = sum(1 for event in events if (event.get("status") or 0) >= 400)
    failed_ratio = failed_count / request_count

    attack_category = "benign"
    if best_score >= 0.45:
        attack_category = "injection"
    elif failed_ratio >= 0.5:
        attack_category = "enumeration"

    historical_consistency = 0.5
    intent_shift_velocity = 0.0
    if previous_attack:
        historical_consistency = 0.85 if previous_attack == best_attack else 0.25
        intent_shift_velocity = 0.0 if previous_attack == best_attack else 0.75

    if best_attack != "benign":
        _session_last_attack[session_id] = best_attack

    confidence = 0.78 if best_score >= 0.45 else 0.35
    memory = "No clear attack detected."
    if best_score >= 0.45:
        memory = f"Rule fallback detected {best_attack} indicators in recent HTTP session."

    return {
        "attack_category": attack_category,
        "web_subtype_scores": scores,
        "evasion_score": max(encoded_or_obfuscated, min(1.0, failed_ratio * 0.5)),
        "historical_intent_consistency": historical_consistency,
        "attack_progression_stage": 0.45 if best_score >= 0.45 else 0.1,
        "intent_shift_velocity": intent_shift_velocity,
        "llm_confidence": confidence,
        "updated_memory_context": memory,
        "_source": "rule_fallback",
    }


# ---------------------------------------------------------------------------
# ES document parsing — extract only the app.* fields we care about
# ---------------------------------------------------------------------------

def parse_source(hit: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return the app-level dict from an ES hit, or None if unreadable."""
    source = hit.get("_source") or {}
    app_doc = source.get("app")
    if isinstance(app_doc, dict):
        return app_doc

    # Fallback: try to decode the raw message field
    for candidate in (
        source.get("message"),
        (source.get("json") or {}).get("log") if isinstance(source.get("json"), dict) else None,
    ):
        if not candidate:
            continue
        try:
            parsed = json.loads(str(candidate).strip())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def clean_event(raw_app: dict[str, Any], timestamp: str) -> Optional[dict[str, Any]]:
    """
    Produce a token-efficient event dict for LLM consumption.

    Rules:
    - Keep only security-relevant fields.
    - Replace HAProxy null sentinel ('-') with None.
    - Skip non-API paths (frontend static assets).
    - Use ISO @timestamp instead of unix ts.
    """
    path = str(raw_app.get("path") or "")
    if not path.startswith(API_PATH_PREFIX):
        return None

    event: dict[str, Any] = {"ts": timestamp}

    keep_fields = (
        "session_id", "client_ip",
        "method", "path", "query", "status",
        "bytes_in", "bytes_out",
        "content_type", "content_length",
        "response_ms",
        "user_agent", "referer",
        "backend",
    )

    for field in keep_fields:
        value = _nullify(raw_app.get(field))
        if field in ("status", "bytes_in", "bytes_out", "response_ms"):
            value = _safe_int(value) if value is not None else None
        event[field] = value

    body_preview = _nullify(raw_app.get("body_preview"))
    if body_preview:
        event["request_body"] = str(body_preview)[:2048]

    return event


# ---------------------------------------------------------------------------
# Session window aggregation — produces the Summary JSON sent to LLM
# ---------------------------------------------------------------------------

def build_session_context(session_id: str, events: list[dict]) -> dict[str, Any]:
    """
    Aggregate a list of clean events for one session into the Summary JSON
    that the LLM will receive as input.
    """
    if not events:
        return {}

    events_sorted = sorted(events, key=lambda e: e["ts"])
    window_start = events_sorted[0]["ts"]
    window_end = events_sorted[-1]["ts"]

    first_seen_ts = _session_first_seen.get(session_id)
    if first_seen_ts is None:
        first_seen_ts = time.time()
        _session_first_seen[session_id] = first_seen_ts
    session_age_s = int(time.time() - first_seen_ts)

    request_count = len(events_sorted)
    failed_count = sum(1 for e in events_sorted if (e.get("status") or 0) >= 400)

    unique_paths = list(dict.fromkeys(
        e["path"] for e in events_sorted if e.get("path")
    ))

    # Determine current backend from most recent event
    current_backend = None
    for e in reversed(events_sorted):
        if e.get("backend"):
            current_backend = e["backend"]
            break

    # Strip per-event fields that are session-level constants to reduce tokens
    # (session_id, client_ip, backend are lifted to the wrapper)
    slim_events = []
    for e in events_sorted:
        slim = {k: v for k, v in e.items()
                if k not in ("session_id", "client_ip", "backend") and v is not None}
        slim_events.append(slim)

    memory = _session_memory.get(session_id, "No prior activity recorded for this session.")

    return {
        "session_id": session_id,
        "client_ip": events_sorted[0].get("client_ip"),
        "window": {
            "start": window_start,
            "end": window_end,
            "session_age_s": session_age_s,
            "request_count": request_count,
            "failed_count": failed_count,
            "current_backend": current_backend,
        },
        "unique_paths": unique_paths,
        "events": slim_events,
        "memory": memory,
    }


# ---------------------------------------------------------------------------
# Rule-based scalar features (computed without LLM)
# ---------------------------------------------------------------------------

def compute_rule_features(session_id: str, events: list[dict]) -> dict[str, float]:
    """
    Compute non-LLM dimensions for the v2 16D state from raw event data.
    Returns named scalars that are combined with LLM or rule-fallback output.
    """
    if not events:
        return {}

    request_count = len(events)

    # session_age_norm — normalize over 600s max window
    first_seen = _session_first_seen.get(session_id, time.time())
    session_age_s = time.time() - first_seen
    session_age_norm = min(1.0, session_age_s / 600.0)

    # interaction_rate_norm — req/s, normalize at anomaly threshold of 5 req/s
    elapsed = max(session_age_s, 1.0)
    interaction_rate_norm = min(1.0, (request_count / elapsed) / 5.0)

    # failed_attempts_norm
    failed_count = sum(1 for e in events if (e.get("status") or 0) >= 400)
    failed_attempts_norm = failed_count / request_count if request_count else 0.0

    # payload_complexity_norm — size anomaly plus obvious payload complexity
    sizes = [e["bytes_in"] for e in events if e.get("bytes_in")]
    if len(sizes) >= 2:
        mean = sum(sizes) / len(sizes)
        variance = sum((x - mean) ** 2 for x in sizes) / len(sizes)
        stddev = math.sqrt(variance) if variance > 0 else 1.0
        # Use largest deviation as the anomaly signal, clipped to [0,1]
        max_z = max(abs(s - mean) / stddev for s in sizes)
        size_signal = min(1.0, max_z / 3.0)  # z=3 -> full anomaly
    elif sizes:
        # Single request: anomaly based on absolute size vs 512 byte baseline
        size_signal = min(1.0, sizes[0] / 2048.0)
    else:
        size_signal = 0.0

    text = _events_text(events)
    dangerous_matches = sum(
        1
        for pattern in (
            r"\bunion\b",
            r"\bselect\b",
            r";|\||&&|`|\$\(",
            r"\{\{|\{%|__class__|__mro__",
            r"169\.254\.169\.254|localhost|127\.0\.0\.1|file://",
            r"%27|%22|%7b|%7d|%2f|\\x[0-9a-f]{2}",
        )
        if re.search(pattern, text, re.IGNORECASE)
    )
    payload_complexity_norm = max(size_signal, min(1.0, dangerous_matches / 3.0))

    # target_diversity_norm — unique paths / total requests
    unique_paths = len(set(e["path"] for e in events if e.get("path")))
    target_diversity_norm = unique_paths / request_count if request_count else 0.0

    # current_route — 0: normal, 1: honeypot
    last_backend = None
    for e in reversed(events):
        if e.get("backend"):
            last_backend = e["backend"]
            break
    current_route = 0.0 if (last_backend is None or last_backend == "normal_api") else 1.0
    engagement_depth_norm = 0.0
    if current_route:
        engagement_depth_norm = min(1.0, (request_count / 10.0) + min(0.3, session_age_norm * 0.3))

    return {
        "session_age_norm": round(session_age_norm, 4),
        "interaction_rate_norm": round(interaction_rate_norm, 4),
        "failed_attempts_norm": round(failed_attempts_norm, 4),
        "payload_complexity_norm": round(payload_complexity_norm, 4),
        "target_diversity_norm": round(target_diversity_norm, 4),
        "current_route": current_route,
        "engagement_depth_norm": round(engagement_depth_norm, 4),
    }


# ---------------------------------------------------------------------------
# LLM — Groq API call for semantic feature extraction
# ---------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = """\
You are a security analyst for an adaptive honeypot system. Your task is to analyze HTTP session data and extract semantic features that help an RL agent decide whether to route traffic to a honeypot.

You will receive a JSON object describing a session window with:
- session_id, client_ip: session identifiers
- window: timing and request statistics
- unique_paths: distinct API paths accessed
- events: list of HTTP requests with method, path, status, request_body, etc.
- memory: summary of prior analysis for this session (or "No prior activity recorded" if first window)

Analyze the session and return ONLY a JSON object with exactly these fields:

{
  "attack_category": "<one of: injection, bruteforce, enumeration, malformed, benign>",
  "web_subtype_scores": [sqli, cmdi, ssti, ssrf],
  "evasion_score": <float 0-1>,
  "historical_intent_consistency": <float 0-1>,
  "attack_progression_stage": <float 0-1>,
  "intent_shift_velocity": <float 0-1>,
  "llm_confidence": <float 0-1>,
  "updated_memory_context": "<concise summary for next analysis window>"
}

Field descriptions:
- attack_category: dominant attack class. Use "benign" for legitimate traffic.
- web_subtype_scores: probability distribution over [sqli, cmdi, ssti, ssrf]. Must sum to ~1.0 for attacks. All zeros for benign traffic.
- evasion_score: how much the attacker is trying to evade detection (encoding, obfuscation, unusual patterns). 0 = no evasion, 1 = heavy evasion.
- historical_intent_consistency: how consistent the attacker's intent is across the session history (from memory). 0 = chaotic/shifting, 1 = focused on one target. Use 0.5 if no prior history.
- attack_progression_stage: 0.0-0.2 = reconnaissance, 0.3-0.5 = active exploitation, 0.6-0.8 = post-exploitation, 0.9-1.0 = lateral movement. Use 0.1 for benign.
- intent_shift_velocity: how fast the attacker is changing tactics compared to memory. 0 = stable, 1 = rapid shifts. Use 0.0 if no prior history.
- llm_confidence: your confidence in this analysis. 0 = guessing, 1 = certain.
- updated_memory_context: a concise summary (max 200 chars) of this session's activity to inform future analysis windows.

Attack type hints:
- SQLi: SQL keywords (SELECT, UNION, OR 1=1, DROP, --, '), database error probing
- CMDi: shell metacharacters (;, |, &&, `), system commands (cat, ls, whoami, /etc/passwd)
- SSTI: template syntax ({{, }}, {%, __class__, __mro__, config)
- SSRF: internal URLs (127.0.0.1, localhost, 169.254.169.254, file://)

Return ONLY valid JSON. No markdown, no explanation, no code blocks."""


def _clamp(value: Any, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _validate_llm_output(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize LLM output fields."""
    scores = raw.get("web_subtype_scores", [0.0, 0.0, 0.0, 0.0])
    if not isinstance(scores, list) or len(scores) != 4:
        scores = [0.0, 0.0, 0.0, 0.0]
    scores = [_clamp(s) for s in scores]

    category = str(raw.get("attack_category", "benign")).lower()
    if category not in ("injection", "bruteforce", "enumeration", "malformed", "benign"):
        category = "benign"

    return {
        "attack_category": category,
        "web_subtype_scores": scores,
        "evasion_score": _clamp(raw.get("evasion_score", 0.0)),
        "historical_intent_consistency": _clamp(raw.get("historical_intent_consistency", 0.5)),
        "attack_progression_stage": _clamp(raw.get("attack_progression_stage", 0.1)),
        "intent_shift_velocity": _clamp(raw.get("intent_shift_velocity", 0.0)),
        "llm_confidence": _clamp(raw.get("llm_confidence", 0.0)),
        "updated_memory_context": str(raw.get("updated_memory_context", ""))[:500],
    }


def call_llm(context: dict[str, Any]) -> Optional[dict[str, Any]]:
    stats["llm_calls"] += 1
    logger.info(json.dumps({
        "event_type": "llm_input_preview",
        "service": "llm-analyzer",
        "session_id": context.get("session_id"),
        "event_count": len(context.get("events") or []),
        "unique_paths": context.get("unique_paths") or [],
        "has_memory": bool(context.get("memory")),
    }, ensure_ascii=True))

    if _groq_client is None:
        return None

    try:
        response = _groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(context, ensure_ascii=True)},
            ],
            temperature=0.1,
            max_tokens=512,
            timeout=GROQ_TIMEOUT,
        )
        raw_text = response.choices[0].message.content.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

        raw_output = json.loads(raw_text)
        validated = _validate_llm_output(raw_output)

        logger.info(json.dumps({
            "event_type": "llm_response",
            "service": "llm-analyzer",
            "session_id": context.get("session_id"),
            "output": validated,
            "model": GROQ_MODEL,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            } if response.usage else {},
        }, ensure_ascii=True))

        return validated

    except json.JSONDecodeError as exc:
        stats["last_error"] = f"llm_json_parse: {exc}"
        logger.warning("LLM returned invalid JSON: %s", exc)
        return None
    except Exception as exc:
        stats["last_error"] = f"llm_call: {exc}"
        logger.warning("LLM call failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Routing helpers
# ---------------------------------------------------------------------------

def route_key(session_id: str, client_ip: str) -> str:
    if session_id:
        return f"sid:{session_id}"
    if client_ip:
        return f"ip:{client_ip}"
    return ""


def should_skip_cooldown(session_id: str, backend: str) -> bool:
    previous = _last_route_by_session.get(session_id)
    now = time.time()
    if previous and previous[0] == backend and now - previous[1] < ROUTE_COOLDOWN_SECONDS:
        return True
    _last_route_by_session[session_id] = (backend, now)
    return False


def remember_service_body(session_id: str, method: str, path: str, body: str) -> None:
    if not session_id or not method or not path or not body:
        return
    now = time.time()
    _recent_service_bodies[(session_id, method, path)] = (body[:2048], now)
    expired = [
        key
        for key, (_, ts) in _recent_service_bodies.items()
        if now - ts > SERVICE_BODY_CACHE_SECONDS
    ]
    for key in expired:
        _recent_service_bodies.pop(key, None)


def get_recent_service_body(session_id: str, method: str, path: str) -> Optional[str]:
    entry = _recent_service_bodies.get((session_id, method, path))
    if not entry:
        return None
    body, ts = entry
    if time.time() - ts > SERVICE_BODY_CACHE_SECONDS:
        _recent_service_bodies.pop((session_id, method, path), None)
        return None
    return body


def build_state_vector(rule_features: dict[str, float], llm_output: Optional[dict]) -> list[float]:
    """
    Assemble the v2 16D state tensor from rule-based features + semantic output.
    `protocol` is intentionally metadata for /decide and is not part of this
    tensor.
    """
    # --- Rule-based scalars ---
    session_age_norm      = rule_features.get("session_age_norm", 0.0)
    interaction_rate_norm = rule_features.get("interaction_rate_norm", 0.0)
    failed_attempts_norm  = rule_features.get("failed_attempts_norm", 0.0)
    payload_complexity    = rule_features.get("payload_complexity_norm", 0.0)
    target_diversity      = rule_features.get("target_diversity_norm", 0.0)
    current_route         = rule_features.get("current_route", 0.0)
    engagement_depth      = rule_features.get("engagement_depth_norm", 0.0)

    # --- LLM semantic features ---
    if llm_output:
        web_subtype_scores          = list(llm_output.get("web_subtype_scores", [0.0, 0.0, 0.0, 0.0]))[:4]
        evasion_score               = float(llm_output.get("evasion_score", 0.0))
        llm_confidence              = float(llm_output.get("llm_confidence", 0.0))
        historical_intent_consistency = float(llm_output.get("historical_intent_consistency", 0.0))
        attack_progression_stage    = float(llm_output.get("attack_progression_stage", 0.0))
        intent_shift_velocity       = float(llm_output.get("intent_shift_velocity", 0.0))
        attack_category             = str(llm_output.get("attack_category", "benign")).lower()

        # Update memory for next window
        session_id = rule_features.get("_session_id", "")
        new_memory = llm_output.get("updated_memory_context")
        if session_id and new_memory:
            _session_memory[session_id] = str(new_memory)
    else:
        web_subtype_scores            = [0.0, 0.0, 0.0, 0.0]
        evasion_score                 = 0.0
        llm_confidence                = 0.0
        historical_intent_consistency = 0.0
        attack_progression_stage      = 0.0
        intent_shift_velocity         = 0.0
        attack_category               = "benign"

    # --- Graceful degradation: scale LLM features by confidence ---
    c = _clamp(llm_confidence)
    target_scores = [_clamp(value) * c for value in web_subtype_scores[:4]]
    while len(target_scores) < 4:
        target_scores.append(0.0)

    credential_score = 0.0
    enumeration_score = 0.0
    if attack_category == "bruteforce":
        credential_score = c
    elif attack_category == "enumeration":
        enumeration_score = c

    intent_stability = historical_intent_consistency * (1.0 - intent_shift_velocity) * c

    state = StateVector(
        session_age_norm=session_age_norm,
        interaction_rate_norm=interaction_rate_norm,
        failed_attempts_norm=failed_attempts_norm,
        payload_complexity_norm=payload_complexity,
        target_diversity_norm=target_diversity,
        current_route=current_route,
        engagement_depth_norm=engagement_depth,
        target_sqli_score=target_scores[0],
        target_cmdi_score=target_scores[1],
        target_ssti_score=target_scores[2],
        target_ssrf_score=target_scores[3],
        target_credential_attack_score=credential_score,
        target_enumeration_score=enumeration_score,
        evasion_score=evasion_score * c,
        attack_progression_stage=attack_progression_stage * c,
        intent_stability_score=intent_stability,
    ).to_list()
    assert len(state) == STATE_DIM, f"state dim mismatch: {len(state)}"
    return state


# ---------------------------------------------------------------------------
# Main analysis pipeline for one session
# ---------------------------------------------------------------------------

def analyze_session(session_id: str, events: list[dict]) -> dict[str, Any]:
    """
    Full pipeline for a single session window:
    1. Build session context (the LLM input JSON)
    2. Call LLM, falling back to rules when provider unavailable
    3. Compute rule-based features
    4. Build v2 16D state vector
    5. Call routing controller
    """
    if not events:
        return {"routed": False, "reason": "no events"}

    context = build_session_context(session_id, events)
    rule_features = compute_rule_features(session_id, events)
    rule_features["_session_id"] = session_id

    llm_output = call_llm(context)
    semantic_source = "llm"
    if llm_output is None:
        llm_output = rule_based_semantic_fallback(session_id, events)
        semantic_source = "rule_fallback"

    state = build_state_vector(rule_features, llm_output)

    # Determine target backend from v2 target scores after confidence scaling.
    subtype_scores = state[7:11]
    subtypes = ["sqli", "cmdi", "ssti", "ssrf"]
    best_idx = max(range(4), key=lambda i: subtype_scores[i])
    best_score = subtype_scores[best_idx]
    attack_type = subtypes[best_idx] if best_score >= ANALYZER_ROUTE_THRESHOLD else None

    if not attack_type:
        return {
            "routed": False,
            "reason": "target_score_too_low",
            "session_id": session_id,
            "semantic_source": semantic_source,
            "best_score": best_score,
        }

    backend = ATTACK_TO_BACKEND[attack_type]
    client_ip = events[0].get("client_ip", "")

    if should_skip_cooldown(session_id, backend):
        return {"routed": False, "reason": "cooldown", "session_id": session_id, "backend": backend}

    payload = {
        "state_schema": STATE_SCHEMA_VERSION,
        "protocol": "http",
        "session_id": session_id or None,
        "source_ip": client_ip or None,
        "state": state,
        "apply_route": ANALYZER_APPLY_ROUTE,
    }
    response = requests.post(f"{ROUTING_CONTROLLER_URL}/decide", json=payload, timeout=5)
    response.raise_for_status()
    body = response.json()
    stats["decisions"] += 1

    logger.info(json.dumps({
        "event_schema_version": "1.0",
        "event_type": "llm_route_decision",
        "ts": now_iso(),
        "service": "llm-analyzer",
        "session_id": session_id,
        "state_schema": STATE_SCHEMA_VERSION,
        "semantic_source": semantic_source,
        "attack_type": attack_type,
        "target_backend": backend,
        "target_scores": {
            "sqli": state[7],
            "cmdi": state[8],
            "ssti": state[9],
            "ssrf": state[10],
        },
        "llm_confidence": llm_output.get("llm_confidence"),
        "controller_response": body,
    }, ensure_ascii=True))

    return {
        "routed": True,
        "attack_type": attack_type,
        "backend": backend,
        "semantic_source": semantic_source,
        "controller_response": body,
    }


# ---------------------------------------------------------------------------
# Elasticsearch polling
# ---------------------------------------------------------------------------

def poll_elasticsearch_once() -> int:
    window_start = datetime.now(timezone.utc) - timedelta(seconds=ANALYZER_WINDOW_SECONDS)
    lower_bound = max(window_start, ANALYZER_STARTED_AT).isoformat()
    query = {
        "size": ANALYZER_MAX_EVENTS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": lower_bound}}},
    }
    response = requests.post(
        f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX}/_search",
        json=query,
        timeout=5,
    )
    response.raise_for_status()
    hits = response.json().get("hits", {}).get("hits", [])

    # Pass 1: collect body_preview from service-level logs (backend/honeypot)
    # keyed by (session_id, method, path) so we can enrich gateway events.
    service_bodies: dict[tuple[str, str, str], str] = {}
    gateway_hits: list[dict] = []

    for hit in reversed(hits):
        event_id = str(hit.get("_id") or "")
        if not event_id or event_id in seen_event_ids:
            continue

        raw_app = parse_source(hit)
        if not raw_app:
            remember_seen(event_id)
            continue

        event_type = str(raw_app.get("event_type") or "")

        # Skip control-plane events
        if event_type == "route_decision":
            remember_seen(event_id)
            continue
        if str(raw_app.get("service") or "") in ("routing-controller", "llm-analyzer"):
            remember_seen(event_id)
            continue

        if event_type in ("honeypot_interaction", "request"):
            # Service-level log with body_preview — index for enrichment
            remember_seen(event_id)
            sid = str(raw_app.get("session_id") or "").strip()
            method = str(raw_app.get("method") or "").upper()
            path = str(raw_app.get("path") or "")
            body = raw_app.get("body_preview")
            if sid and body:
                body_preview = str(body)[:2048]
                service_bodies[(sid, method, path)] = body_preview
                remember_service_body(sid, method, path, body_preview)
            continue

        # Gateway event — collect for pass 2
        gateway_hits.append(hit)

    # Pass 2: process gateway events, enriching with body_preview from pass 1
    new_count = 0
    for hit in gateway_hits:
        event_id = str(hit.get("_id") or "")
        if event_id in seen_event_ids:
            continue
        remember_seen(event_id)

        raw_app = parse_source(hit)
        if not raw_app:
            continue

        # Enrich gateway event with body_preview from service log
        sid = str(raw_app.get("session_id") or "").strip()
        method = str(raw_app.get("method") or "").upper()
        path = str(raw_app.get("path") or "")
        body_key = (sid, method, path)
        if body_key in service_bodies and not raw_app.get("body_preview"):
            raw_app["body_preview"] = service_bodies[body_key]
        elif not raw_app.get("body_preview"):
            cached_body = get_recent_service_body(sid, method, path)
            if cached_body:
                raw_app["body_preview"] = cached_body

        timestamp = (hit.get("_source") or {}).get("@timestamp", now_iso())
        event = clean_event(raw_app, timestamp)
        if not event:
            continue

        if not sid:
            continue

        if sid not in _session_first_seen:
            _session_first_seen[sid] = time.time()

        _pending_events[sid].append(event)
        new_count += 1

    return new_count


# ---------------------------------------------------------------------------
# Worker loop — collect events, then analyze per-session every interval
# ---------------------------------------------------------------------------

def worker_loop() -> None:
    while True:
        if ANALYZER_ENABLED:
            try:
                new_events = poll_elasticsearch_once()
                stats["last_poll_at"] = now_iso()
                stats["last_error"] = ""

                if new_events:
                    logger.info("analyzer polled %d new events across %d sessions",
                                new_events, len(_pending_events))

                # Drain pending events and analyze each session
                sessions_to_analyze = list(_pending_events.keys())
                for session_id in sessions_to_analyze:
                    events = _pending_events.pop(session_id, [])
                    if events:
                        analyze_session(session_id, events)

            except Exception as exc:  # noqa: BLE001
                stats["last_error"] = str(exc)
                logger.warning("analyzer poll failed: %s", exc)

        time.sleep(ANALYZER_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# FastAPI lifecycle & endpoints
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup() -> None:
    thread = threading.Thread(target=worker_loop, name="analyzer-worker", daemon=True)
    thread.start()


@app.get("/health")
def health() -> dict[str, Any]:
    if not DEBUG_EXPOSURE:
        return {"status": "ok"}
    return AnalyzerStats(
        enabled=ANALYZER_ENABLED,
        state_schema=STATE_SCHEMA_VERSION,
        state_dim=STATE_DIM,
        elasticsearch_url=ELASTICSEARCH_URL,
        routing_controller_url=ROUTING_CONTROLLER_URL,
        seen_events=len(seen_event_ids),
        decisions=int(stats["decisions"]),
        llm_calls=int(stats["llm_calls"]),
        last_error=str(stats["last_error"]),
        last_poll_at=str(stats["last_poll_at"]),
    ).model_dump()


@app.get("/sessions")
def list_sessions() -> dict[str, Any]:
    require_debug_exposure()
    return {
        "status": "ok",
        "active_sessions": len(_session_first_seen),
        "pending_event_counts": {sid: len(evts) for sid, evts in _pending_events.items()},
        "memory_keys": list(_session_memory.keys()),
    }


@app.get("/session/{session_id}/context")
def get_session_context(session_id: str) -> dict[str, Any]:
    """Return the current accumulated events and context for a session (debug)."""
    require_debug_exposure()
    events = list(_pending_events.get(session_id, []))
    context = build_session_context(session_id, events) if events else {}
    rule_features = compute_rule_features(session_id, events) if events else {}
    return {
        "status": "ok",
        "session_id": session_id,
        "event_count": len(events),
        "rule_features": rule_features,
        "llm_context": context,
    }
