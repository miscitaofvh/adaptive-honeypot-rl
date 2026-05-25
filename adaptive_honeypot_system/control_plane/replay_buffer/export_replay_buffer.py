from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

CONTROL_PLANE_DIR = Path(__file__).resolve().parents[1]
RL_AGENT_DIR = CONTROL_PLANE_DIR / "rl_agent"

for path in (CONTROL_PLANE_DIR, RL_AGENT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agent import (  # noqa: E402
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    action_backend,
    action_name,
)
from state_builder import STATE_DIM, STATE_FIELD_NAMES, STATE_SCHEMA_VERSION, validate_state  # noqa: E402

POT_BACKENDS = {"sqli_api", "ssti_api", "cmdi_api", "ssrf_api"}
WEB_SCORE_TO_ACTION = [
    ("sqli", ACTION_ROUTE_SQLI),
    ("cmdi", ACTION_ROUTE_CMDI),
    ("ssti", ACTION_ROUTE_SSTI),
    ("ssrf", ACTION_ROUTE_SSRF),
]
SERVICE_TO_BACKEND = {
    "sqli-honeypot": "sqli_api",
    "ssti-honeypot": "ssti_api",
    "cmdi-honeypot": "cmdi_api",
    "ssrf-honeypot": "ssrf_api",
    "real-backend": "normal_api",
}
POT_TYPE_TO_BACKEND = {
    "sql-injection": "sqli_api",
    "template-injection": "ssti_api",
    "command-injection": "cmdi_api",
    "server-side-request-forgery": "ssrf_api",
}


@dataclass
class LoggedEvent:
    timestamp: float
    app: dict[str, Any]


@dataclass
class Decision:
    timestamp: float
    decision_id: str
    session_id: str
    protocol: str
    state: list[float]
    action_id: int
    backend: str
    route_applied: bool
    reason: str
    target_scores: dict[str, float]
    raw: dict[str, Any]


def parse_ts(value: Any, fallback: Optional[float] = None) -> float:
    if value is None or value == "":
        if fallback is not None:
            return fallback
        return datetime.now(timezone.utc).timestamp()

    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number = number / 1000.0
        return number

    text = str(value).strip()
    if not text:
        return parse_ts(None, fallback)
    try:
        number = float(text)
        return parse_ts(number, fallback)
    except ValueError:
        pass

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return parse_ts(None, fallback)


def iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def extract_app_doc(raw: dict[str, Any]) -> tuple[Optional[dict[str, Any]], Any]:
    if "_source" in raw:
        source = raw.get("_source") or {}
        app_doc = source.get("app")
        if isinstance(app_doc, dict):
            return app_doc, source.get("@timestamp")
        message = source.get("message")
        if isinstance(message, str):
            try:
                parsed = json.loads(message.strip())
                if isinstance(parsed, dict):
                    return parsed, source.get("@timestamp")
            except json.JSONDecodeError:
                return None, source.get("@timestamp")
        return None, source.get("@timestamp")

    if "app" in raw and isinstance(raw["app"], dict):
        return raw["app"], raw.get("@timestamp")

    if "event_type" in raw:
        return raw, raw.get("@timestamp")

    return None, raw.get("@timestamp")


def normalize_events(raw_docs: Iterable[dict[str, Any]]) -> list[LoggedEvent]:
    events: list[LoggedEvent] = []
    for raw in raw_docs:
        app_doc, source_ts = extract_app_doc(raw)
        if not app_doc:
            continue
        timestamp = parse_ts(app_doc.get("ts"), parse_ts(source_ts) if source_ts else None)
        events.append(LoggedEvent(timestamp=timestamp, app=app_doc))
    events.sort(key=lambda event: event.timestamp)
    return events


def load_jsonl(path: Path) -> list[LoggedEvent]:
    raw_docs: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"Expected JSON object at {path}:{line_no}")
            raw_docs.append(raw)
    return normalize_events(raw_docs)


def es_search(
    *,
    elasticsearch_url: str,
    index: str,
    time_min: str,
    time_max: str,
    max_events: int,
) -> list[LoggedEvent]:
    url = f"{elasticsearch_url.rstrip('/')}/{index}/_search"
    payload = {
        "size": max_events,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "track_total_hits": False,
        "_source": ["@timestamp", "app", "message"],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": time_min,
                    "lte": time_max,
                }
            }
        },
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not query Elasticsearch at {url}: {exc}") from exc

    hits = body.get("hits", {}).get("hits", [])
    if not isinstance(hits, list):
        return []
    return normalize_events([hit for hit in hits if isinstance(hit, dict)])


def event_type(event: LoggedEvent) -> str:
    return str(event.app.get("event_type") or "")


def event_session(event: LoggedEvent) -> str:
    sid = str(event.app.get("session_id") or "").strip()
    if sid == "-":
        return ""
    return sid


def backend_from_event(app: dict[str, Any]) -> str:
    backend = str(app.get("backend") or "").strip()
    if backend and backend != "-":
        return backend

    service = str(app.get("service") or "").strip()
    if service in SERVICE_TO_BACKEND:
        return SERVICE_TO_BACKEND[service]

    pot_type = str(app.get("pot_type") or "").strip()
    if pot_type in POT_TYPE_TO_BACKEND:
        return POT_TYPE_TO_BACKEND[pot_type]

    return ""


def status_code(app: dict[str, Any]) -> int:
    for key in ("status", "status_code"):
        value = app.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def state_target_scores(state: list[float]) -> dict[str, float]:
    return {
        "sqli": float(state[7]),
        "cmdi": float(state[8]),
        "ssti": float(state[9]),
        "ssrf": float(state[10]),
        "credential_attack": float(state[11]),
        "enumeration": float(state[12]),
    }


def normalize_scores(raw_scores: Any, state: list[float]) -> dict[str, float]:
    if isinstance(raw_scores, dict):
        scores = {str(key): float(value) for key, value in raw_scores.items() if _is_number(value)}
        if scores:
            return scores
    return state_target_scores(state)


def _is_number(value: Any) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def infer_optimal_action(scores: dict[str, float], threshold: float) -> int:
    web_scores = [(name, scores.get(name, 0.0), action) for name, action in WEB_SCORE_TO_ACTION]
    _, best_score, best_action = max(web_scores, key=lambda item: item[1])
    if best_score >= threshold:
        return best_action
    return ACTION_KEEP_NORMAL


def best_score(scores: dict[str, float]) -> float:
    return max((scores.get(name, 0.0) for name, _ in WEB_SCORE_TO_ACTION), default=0.0)


def parse_decision(event: LoggedEvent) -> Optional[Decision]:
    app = event.app
    if event_type(event) not in {"rl_state_decision", "route_decision"}:
        return None

    session_id = event_session(event)
    if not session_id:
        return None

    raw_state = app.get("state")
    if not isinstance(raw_state, list):
        return None
    try:
        state = validate_state(raw_state)
    except ValueError:
        return None

    try:
        action_id = int(app.get("action_id", ACTION_KEEP_NORMAL))
    except (TypeError, ValueError):
        action_id = ACTION_KEEP_NORMAL

    backend = str(app.get("backend") or action_backend(action_id))
    decision_id = str(app.get("decision_id") or f"{session_id}:{event.timestamp:.6f}:{action_id}")
    target_scores = normalize_scores(app.get("target_scores"), state)

    return Decision(
        timestamp=event.timestamp,
        decision_id=decision_id,
        session_id=session_id,
        protocol=str(app.get("protocol") or "http").lower(),
        state=state,
        action_id=action_id,
        backend=backend,
        route_applied=bool(app.get("route_applied", False)),
        reason=str(app.get("decision_reason") or ""),
        target_scores=target_scores,
        raw=app,
    )


def collect_decisions(events: list[LoggedEvent]) -> list[Decision]:
    by_id: dict[str, tuple[int, Decision]] = {}
    priority = {"route_decision": 1, "rl_state_decision": 2}
    for event in events:
        decision = parse_decision(event)
        if not decision:
            continue
        event_priority = priority.get(event_type(event), 0)
        previous = by_id.get(decision.decision_id)
        if previous is None or event_priority >= previous[0]:
            by_id[decision.decision_id] = (event_priority, decision)
    return sorted((item[1] for item in by_id.values()), key=lambda decision: decision.timestamp)


def group_outcome_events(events: list[LoggedEvent]) -> dict[str, list[LoggedEvent]]:
    grouped: dict[str, list[LoggedEvent]] = defaultdict(list)
    for event in events:
        if event_type(event) not in {"gateway_request", "request", "honeypot_interaction"}:
            continue
        session_id = event_session(event)
        if session_id:
            grouped[session_id].append(event)
    for session_events in grouped.values():
        session_events.sort(key=lambda event: event.timestamp)
    return grouped


def events_in_window(events: list[LoggedEvent], start: float, end: float) -> list[LoggedEvent]:
    return [event for event in events if start <= event.timestamp <= end]


def reward_for_transition(
    *,
    decision: Decision,
    outcome_events: list[LoggedEvent],
    next_decision: Optional[Decision],
    attack_threshold: float,
) -> tuple[float, dict[str, Any], int]:
    scores = decision.target_scores
    optimal_action = infer_optimal_action(scores, attack_threshold)
    evidence_score = best_score(scores)
    action_id = decision.action_id
    action_backend_name = action_backend(action_id)

    backends = [backend_from_event(event.app) for event in outcome_events]
    honeypot_events = [backend for backend in backends if backend in POT_BACKENDS]
    matching_honeypot_count = sum(1 for backend in honeypot_events if backend == action_backend_name)
    wrong_honeypot_count = sum(1 for backend in honeypot_events if backend and backend != action_backend_name)
    normal_count = sum(1 for backend in backends if backend == "normal_api")
    status_codes = [status_code(event.app) for event in outcome_events]
    server_errors = sum(1 for code in status_codes if code >= 500)
    client_errors = sum(1 for code in status_codes if 400 <= code < 500)
    dwell_seconds = 0.0
    if outcome_events:
        dwell_seconds = max(0.0, outcome_events[-1].timestamp - decision.timestamp)

    engagement_gain = 0.0
    progression_gain = 0.0
    if next_decision:
        engagement_gain = max(0.0, float(next_decision.state[6]) - float(decision.state[6]))
        progression_gain = max(0.0, float(next_decision.state[14]) - float(decision.state[14]))

    components: dict[str, Any] = {
        "evidence_score": round(evidence_score, 4),
        "optimal_action": optimal_action,
        "optimal_action_name": action_name(optimal_action),
        "outcome_event_count": len(outcome_events),
        "honeypot_event_count": len(honeypot_events),
        "matching_honeypot_count": matching_honeypot_count,
        "wrong_honeypot_count": wrong_honeypot_count,
        "normal_event_count": normal_count,
        "server_errors": server_errors,
        "client_errors": client_errors,
        "dwell_seconds": round(dwell_seconds, 3),
        "engagement_gain": round(engagement_gain, 4),
        "progression_gain": round(progression_gain, 4),
    }

    reward = 0.0
    if action_id == ACTION_KEEP_NORMAL:
        if optimal_action == ACTION_KEEP_NORMAL:
            reward += 0.45
            components["classification_reward"] = 0.45
        else:
            reward -= 0.90
            components["missed_attack_penalty"] = -0.90
        if normal_count:
            normal_bonus = min(0.15, normal_count * 0.03)
            reward += normal_bonus
            components["normal_continuity_bonus"] = round(normal_bonus, 4)
        if honeypot_events:
            penalty = min(0.50, len(honeypot_events) * 0.10)
            reward -= penalty
            components["unexpected_honeypot_penalty"] = round(-penalty, 4)
        if server_errors:
            penalty = min(0.50, server_errors * 0.10)
            reward -= penalty
            components["normal_error_penalty"] = round(-penalty, 4)
    else:
        if optimal_action == ACTION_KEEP_NORMAL:
            reward -= 1.20
            components["false_positive_penalty"] = -1.20
        elif action_id == optimal_action:
            reward += 0.80
            components["route_match_reward"] = 0.80
        else:
            reward -= 1.00
            components["wrong_honeypot_penalty"] = -1.00

        if matching_honeypot_count:
            bonus = min(0.80, matching_honeypot_count * 0.20)
            reward += bonus
            components["honeypot_engagement_bonus"] = round(bonus, 4)
        else:
            reward -= 0.35
            components["no_honeypot_followup_penalty"] = -0.35

        if wrong_honeypot_count:
            penalty = min(0.80, wrong_honeypot_count * 0.25)
            reward -= penalty
            components["wrong_backend_outcome_penalty"] = round(-penalty, 4)

        dwell_bonus = min(0.40, (dwell_seconds / 60.0) * 0.40)
        engagement_bonus = min(0.35, engagement_gain * 0.60)
        progression_bonus = min(0.25, progression_gain * 0.40)
        reward += dwell_bonus + engagement_bonus + progression_bonus
        components["dwell_bonus"] = round(dwell_bonus, 4)
        components["engagement_state_bonus"] = round(engagement_bonus, 4)
        components["progression_bonus"] = round(progression_bonus, 4)

        if server_errors and action_id != ACTION_ROUTE_SQLI:
            penalty = min(0.25, server_errors * 0.05)
            reward -= penalty
            components["contract_error_penalty"] = round(-penalty, 4)

    if action_id != ACTION_KEEP_NORMAL and not decision.route_applied and decision.reason not in {"cooldown"}:
        reward -= 0.20
        components["route_not_applied_penalty"] = -0.20

    reward = max(-2.0, min(2.5, reward))
    return round(reward, 4), components, optimal_action


def build_transitions(
    *,
    decisions: list[Decision],
    outcomes_by_session: dict[str, list[LoggedEvent]],
    horizon_seconds: float,
    session_timeout_seconds: float,
    attack_threshold: float,
) -> list[dict[str, Any]]:
    by_session: dict[str, list[Decision]] = defaultdict(list)
    for decision in decisions:
        by_session[decision.session_id].append(decision)
    for session_decisions in by_session.values():
        session_decisions.sort(key=lambda decision: decision.timestamp)

    transitions: list[dict[str, Any]] = []
    for session_id, session_decisions in sorted(by_session.items()):
        outcomes = outcomes_by_session.get(session_id, [])
        for step, decision in enumerate(session_decisions):
            next_decision = session_decisions[step + 1] if step + 1 < len(session_decisions) else None
            timed_out = (
                next_decision is None
                or next_decision.timestamp - decision.timestamp > session_timeout_seconds
            )
            next_state = decision.state if timed_out or next_decision is None else next_decision.state
            horizon_end = decision.timestamp + horizon_seconds
            if next_decision is not None:
                horizon_end = min(horizon_end, next_decision.timestamp)
            outcome_window = events_in_window(outcomes, decision.timestamp, horizon_end)
            reward, reward_components, optimal_action = reward_for_transition(
                decision=decision,
                outcome_events=outcome_window,
                next_decision=None if timed_out else next_decision,
                attack_threshold=attack_threshold,
            )

            transitions.append({
                "session_id": session_id,
                "decision_id": decision.decision_id,
                "step": step,
                "protocol": decision.protocol,
                "state_schema": STATE_SCHEMA_VERSION,
                "state_fields": STATE_FIELD_NAMES,
                "state": decision.state,
                "action": decision.action_id,
                "action_name": action_name(decision.action_id),
                "backend": decision.backend,
                "reward": reward,
                "reward_components": reward_components,
                "next_state": next_state,
                "done": bool(timed_out),
                "optimal_action": optimal_action,
                "window_start": iso_utc(decision.timestamp),
                "window_end": iso_utc(horizon_end),
            })
    return transitions


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
            count += 1
    return count


def parse_args() -> argparse.Namespace:
    default_output = CONTROL_PLANE_DIR / "rl_agent" / "data" / "replay_buffer.jsonl"
    parser = argparse.ArgumentParser(
        description="Export offline RL transitions from control-plane decisions and traffic logs.",
    )
    parser.add_argument("--input-jsonl", type=Path, help="Optional local JSONL event file instead of Elasticsearch.")
    parser.add_argument("--output", type=Path, default=default_output, help="Output transitions JSONL path.")
    parser.add_argument("--elasticsearch-url", default=os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"))
    parser.add_argument("--index", default=os.getenv("ELASTICSEARCH_INDEX", "honeypot-logs-*"))
    parser.add_argument("--lookback-minutes", type=int, default=180)
    parser.add_argument("--time-min", help="ISO8601 lower bound for @timestamp.")
    parser.add_argument("--time-max", help="ISO8601 upper bound for @timestamp.")
    parser.add_argument("--max-events", type=int, default=10_000)
    parser.add_argument("--horizon-seconds", type=float, default=60.0)
    parser.add_argument("--session-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--attack-threshold", type=float, default=0.45)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.input_jsonl:
        events = load_jsonl(args.input_jsonl)
        source = str(args.input_jsonl)
    else:
        now = datetime.now(timezone.utc)
        time_min = args.time_min or (now - timedelta(minutes=args.lookback_minutes)).isoformat()
        time_max = args.time_max or now.isoformat()
        events = es_search(
            elasticsearch_url=args.elasticsearch_url,
            index=args.index,
            time_min=time_min,
            time_max=time_max,
            max_events=args.max_events,
        )
        source = f"{args.elasticsearch_url.rstrip('/')}/{args.index}"

    decisions = collect_decisions(events)
    outcomes_by_session = group_outcome_events(events)
    transitions = build_transitions(
        decisions=decisions,
        outcomes_by_session=outcomes_by_session,
        horizon_seconds=args.horizon_seconds,
        session_timeout_seconds=args.session_timeout_seconds,
        attack_threshold=args.attack_threshold,
    )
    written = write_jsonl(args.output, transitions)
    action_counts = Counter(row["action_name"] for row in transitions)
    session_count = len({row["session_id"] for row in transitions})

    print("Replay buffer export complete")
    print(f"- Source: {source}")
    print(f"- Events read: {len(events)}")
    print(f"- Decisions found: {len(decisions)}")
    print(f"- Sessions exported: {session_count}")
    print(f"- Transitions written: {written}")
    print(f"- Output: {args.output}")
    print(f"- Action counts: {dict(action_counts)}")
    if written == 0:
        print("- Note: no transitions were written. Ensure rl_state_decision logs exist in the selected time range.")


if __name__ == "__main__":
    main()
