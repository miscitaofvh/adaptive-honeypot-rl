from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from fastapi import FastAPI, HTTPException
from groq import Groq
from pydantic import BaseModel, Field


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
ANALYZER_STARTED_AT = datetime.now(timezone.utc)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "15"))

_groq_client: Optional[Groq] = None
if GROQ_API_KEY:
    _groq_client = Groq(api_key=GROQ_API_KEY)
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

seen_event_ids: OrderedDict[str, float] = OrderedDict()
# session_id → list of clean event dicts accumulated since last analysis cycle
_pending_events: dict[str, list[dict]] = defaultdict(list)

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
    Compute the non-LLM dimensions of the 24D state vector from raw event data.
    Returns a dict of named scalars; the state builder in apply_decision() will
    combine these with LLM output.
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

    # content_size_anomaly — z-score of bytes_in vs rolling mean/stddev
    sizes = [e["bytes_in"] for e in events if e.get("bytes_in")]
    if len(sizes) >= 2:
        mean = sum(sizes) / len(sizes)
        variance = sum((x - mean) ** 2 for x in sizes) / len(sizes)
        stddev = math.sqrt(variance) if variance > 0 else 1.0
        # Use largest deviation as the anomaly signal, clipped to [0,1]
        max_z = max(abs(s - mean) / stddev for s in sizes)
        content_size_anomaly = min(1.0, max_z / 3.0)  # z=3 → full anomaly
    elif sizes:
        # Single request: anomaly based on absolute size vs 512 byte baseline
        content_size_anomaly = min(1.0, sizes[0] / 2048.0)
    else:
        content_size_anomaly = 0.0

    # probe_diversity_norm — unique paths / total requests
    unique_paths = len(set(e["path"] for e in events if e.get("path")))
    probe_diversity_norm = unique_paths / request_count if request_count else 0.0

    # current_route — 0: normal, 1: honeypot
    last_backend = None
    for e in reversed(events):
        if e.get("backend"):
            last_backend = e["backend"]
            break
    current_route = 0.0 if (last_backend is None or last_backend == "normal_api") else 1.0

    return {
        "session_age_norm": round(session_age_norm, 4),
        "interaction_rate_norm": round(interaction_rate_norm, 4),
        "failed_attempts_norm": round(failed_attempts_norm, 4),
        "content_size_anomaly": round(content_size_anomaly, 4),
        "probe_diversity_norm": round(probe_diversity_norm, 4),
        "current_route": current_route,
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
        "payload": context,
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


def build_state_vector(rule_features: dict[str, float], llm_output: Optional[dict]) -> list[float]:
    """
    Assemble the full 24D state tensor from rule-based features + LLM output.
    When llm_output is None (stub/error), LLM dimensions collapse toward 0
    via llm_confidence=0, forcing the RL agent to rely on rule-based signals.
    """
    # --- Protocol (4D) — always HTTP in this milestone ---
    protocol_onehot = [1.0, 0.0, 0.0, 0.0]

    # --- Rule-based scalars ---
    session_age_norm      = rule_features.get("session_age_norm", 0.0)
    interaction_rate_norm = rule_features.get("interaction_rate_norm", 0.0)
    failed_attempts_norm  = rule_features.get("failed_attempts_norm", 0.0)
    content_size_anomaly  = rule_features.get("content_size_anomaly", 0.0)
    probe_diversity_norm  = rule_features.get("probe_diversity_norm", 0.0)
    current_route         = rule_features.get("current_route", 0.0)

    # --- LLM semantic features ---
    if llm_output:
        cat_map = {"injection": 0, "bruteforce": 1, "enumeration": 2, "malformed": 3}
        cat_idx = cat_map.get(str(llm_output.get("attack_category", "")).lower(), 0)
        attack_category_onehot = [1.0 if i == cat_idx else 0.0 for i in range(4)]

        web_subtype_scores          = list(llm_output.get("web_subtype_scores", [0.0, 0.0, 0.0, 0.0]))[:4]
        evasion_score               = float(llm_output.get("evasion_score", 0.0))
        llm_confidence              = float(llm_output.get("llm_confidence", 0.0))
        historical_intent_consistency = float(llm_output.get("historical_intent_consistency", 0.0))
        attack_progression_stage    = float(llm_output.get("attack_progression_stage", 0.0))
        intent_shift_velocity       = float(llm_output.get("intent_shift_velocity", 0.0))

        # Update memory for next window
        session_id = rule_features.get("_session_id", "")
        new_memory = llm_output.get("updated_memory_context")
        if session_id and new_memory:
            _session_memory[session_id] = str(new_memory)
    else:
        attack_category_onehot        = [0.0, 0.0, 0.0, 0.0]
        web_subtype_scores            = [0.0, 0.0, 0.0, 0.0]
        evasion_score                 = 0.0
        llm_confidence                = 0.0
        historical_intent_consistency = 0.0
        attack_progression_stage      = 0.0
        intent_shift_velocity         = 0.0

    # --- Graceful degradation: scale LLM features by confidence ---
    c = llm_confidence
    effective_category  = [v * c for v in attack_category_onehot]
    effective_subtype   = [v * c for v in web_subtype_scores]
    effective_evasion   = evasion_score * c
    effective_hist      = historical_intent_consistency * c
    effective_prog      = attack_progression_stage * c
    effective_shift_vel = intent_shift_velocity * c

    # attack_vector_shift — placeholder 0 (would need previous-window state to compute)
    attack_vector_shift = 0.0

    # memory_decay_weight — always 1.0 (in-memory store, no time decay yet)
    memory_decay_weight = 1.0 * c if llm_output else 0.0

    state = [
        *protocol_onehot,           # 4
        session_age_norm,           # 1
        interaction_rate_norm,      # 1
        failed_attempts_norm,       # 1
        content_size_anomaly,       # 1
        probe_diversity_norm,       # 1
        *effective_category,        # 4
        *effective_subtype,         # 4
        effective_evasion,          # 1
        current_route,              # 1
        attack_vector_shift,        # 1
        effective_hist,             # 1
        effective_prog,             # 1
        memory_decay_weight,        # 1
        effective_shift_vel,        # 1
    ]
    assert len(state) == 24, f"state dim mismatch: {len(state)}"
    return state


# ---------------------------------------------------------------------------
# Main analysis pipeline for one session
# ---------------------------------------------------------------------------

def analyze_session(session_id: str, events: list[dict]) -> dict[str, Any]:
    """
    Full pipeline for a single session window:
    1. Build session context (the LLM input JSON)
    2. Call LLM (stub for now)
    3. Compute rule-based features
    4. Build 24D state vector
    5. Call routing controller
    """
    if not events:
        return {"routed": False, "reason": "no events"}

    context = build_session_context(session_id, events)
    rule_features = compute_rule_features(session_id, events)
    rule_features["_session_id"] = session_id

    llm_output = call_llm(context)

    if llm_output is None:
        return {
            "routed": False,
            "reason": "llm_no_output",
            "session_id": session_id,
            "rule_features": rule_features,
            "context_event_count": len(events),
        }

    # Determine target backend from LLM subtype scores
    subtype_scores = llm_output.get("web_subtype_scores", [0, 0, 0, 0])
    subtypes = ["sqli", "cmdi", "ssti", "ssrf"]
    best_idx = max(range(4), key=lambda i: subtype_scores[i])
    best_score = subtype_scores[best_idx]
    attack_type = subtypes[best_idx] if best_score >= 0.45 else None

    if not attack_type:
        return {"routed": False, "reason": "llm_confidence_too_low", "session_id": session_id}

    backend = ATTACK_TO_BACKEND[attack_type]
    client_ip = events[0].get("client_ip", "")

    if should_skip_cooldown(session_id, backend):
        return {"routed": False, "reason": "cooldown", "session_id": session_id, "backend": backend}

    state = build_state_vector(rule_features, llm_output)

    payload = {
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
        "attack_type": attack_type,
        "target_backend": backend,
        "llm_confidence": llm_output.get("llm_confidence"),
        "controller_response": body,
    }, ensure_ascii=True))

    return {"routed": True, "attack_type": attack_type, "backend": backend, "controller_response": body}


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
                service_bodies[(sid, method, path)] = str(body)[:2048]
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
