from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

SYSTEM_DIR = Path(__file__).resolve().parents[2]
DEFAULT_LOGS_DIR = SYSTEM_DIR / "logs"

POT_BACKENDS = {"sqli_api", "ssti_api", "cmdi_api", "ssrf_api"}
NORMAL_BACKEND = "normal_api"
DECISION_EVENTS = {"rl_state_decision", "llm_route_decision", "route_decision"}
SERVICE_EVENTS = {"request", "honeypot_interaction"}
BACKEND_TARGET_SURFACE = {
    "sqli_api": "articles_search",
    "ssti_api": "tools_preview",
    "cmdi_api": "tools_ping",
    "ssrf_api": "tools_fetch",
}


@dataclass(frozen=True)
class Event:
    timestamp: float
    app: dict[str, Any]
    source_path: str


@dataclass(frozen=True)
class RouteDecision:
    timestamp: float
    decision_id: str
    session_id: str
    selected_backend: str
    expected_backend: str
    route_applied: bool
    is_attack_window: bool
    route_correct_by_semantic_label: Optional[bool]
    raw: dict[str, Any]


def parse_ts(value: Any) -> float:
    if value is None or value == "":
        return datetime.now(timezone.utc).timestamp()
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000.0
        return number
    text = str(value).strip()
    if not text:
        return parse_ts(None)
    try:
        return parse_ts(float(text))
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return parse_ts(None)


def ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(numerator / float(denominator), 6)


def mean(values: Iterable[float]) -> Optional[float]:
    values = list(values)
    if not values:
        return None
    return round(sum(values) / float(len(values)), 6)


def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    values = sorted(values)
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 6)
    pos = (len(values) - 1) * pct
    lower = int(pos)
    upper = min(lower + 1, len(values) - 1)
    weight = pos - lower
    return round(values[lower] * (1.0 - weight) + values[upper] * weight, 6)


def read_jsonl(path: Path) -> list[Event]:
    events: list[Event] = []
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
                continue
            app = raw.get("app") if isinstance(raw.get("app"), dict) else raw
            if not isinstance(app, dict):
                continue
            events.append(Event(timestamp=parse_ts(app.get("ts") or raw.get("@timestamp")), app=app, source_path=str(path)))
    return events


def iter_log_files(logs_dir: Path) -> list[Path]:
    if not logs_dir.exists():
        return []
    return sorted(path for path in logs_dir.rglob("*.jsonl") if path.is_file())


def load_events(logs_dir: Path) -> list[Event]:
    events: list[Event] = []
    for path in iter_log_files(logs_dir):
        events.extend(read_jsonl(path))
    events.sort(key=lambda event: event.timestamp)
    return events


def event_type(event: Event) -> str:
    return str(event.app.get("event_type") or "")


def session_id(event: Event) -> str:
    sid = str(event.app.get("session_id") or "").strip()
    return "" if sid == "-" else sid


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return as_bool(value)


def backend_from_service_event(app: dict[str, Any]) -> str:
    backend = str(app.get("observed_backend") or app.get("backend") or "").strip()
    if backend:
        return backend
    service = str(app.get("service") or "")
    mapping = {
        "real-backend": NORMAL_BACKEND,
        "sqli-honeypot": "sqli_api",
        "ssti-honeypot": "ssti_api",
        "cmdi-honeypot": "cmdi_api",
        "ssrf-honeypot": "ssrf_api",
    }
    return mapping.get(service, "")


def selected_backend(app: dict[str, Any]) -> str:
    backend = str(app.get("selected_backend") or app.get("backend") or "").strip()
    if backend:
        return backend
    response = app.get("controller_response")
    if isinstance(response, dict):
        return str(response.get("backend") or "").strip()
    return ""


def expected_backend(app: dict[str, Any]) -> str:
    return str(app.get("expected_backend_by_semantic_label") or app.get("target_backend") or "").strip()


def parse_decision(event: Event) -> Optional[RouteDecision]:
    app = event.app
    if event_type(event) not in DECISION_EVENTS:
        return None
    sid = session_id(event)
    if not sid:
        return None
    backend = selected_backend(app)
    expected = expected_backend(app)
    response = app.get("controller_response") if isinstance(app.get("controller_response"), dict) else {}
    route_applied = as_bool(app.get("route_applied", response.get("route_applied", False)))
    decision_id = str(app.get("decision_id") or f"{sid}:{event.timestamp:.6f}:{backend}")
    is_attack = as_bool(app.get("is_attack_window")) or expected in POT_BACKENDS
    return RouteDecision(
        timestamp=event.timestamp,
        decision_id=decision_id,
        session_id=sid,
        selected_backend=backend,
        expected_backend=expected,
        route_applied=route_applied,
        is_attack_window=is_attack,
        route_correct_by_semantic_label=optional_bool(app.get("route_correct_by_semantic_label")),
        raw=app,
    )


def collect_decisions(events: list[Event]) -> list[RouteDecision]:
    by_id: dict[str, tuple[int, RouteDecision]] = {}
    priority = {"route_decision": 1, "llm_route_decision": 2, "rl_state_decision": 3}
    for event in events:
        decision = parse_decision(event)
        if decision is None:
            continue
        key = decision.decision_id
        event_priority = priority.get(event_type(event), 0)
        previous = by_id.get(key)
        if previous is None or event_priority >= previous[0]:
            by_id[key] = (event_priority, decision)
    return sorted((item[1] for item in by_id.values()), key=lambda decision: decision.timestamp)


def group_service_events(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event_type(event) not in SERVICE_EVENTS:
            continue
        sid = session_id(event)
        if not sid:
            continue
        grouped[sid].append(event)
    for rows in grouped.values():
        rows.sort(key=lambda event: event.timestamp)
    return grouped


def first_applied_route(decisions: list[RouteDecision]) -> Optional[RouteDecision]:
    for decision in sorted(decisions, key=lambda item: item.timestamp):
        if decision.route_applied and decision.selected_backend in POT_BACKENDS:
            return decision
    return None


def applied_pot_routes(decisions: list[RouteDecision]) -> list[RouteDecision]:
    return [
        decision
        for decision in sorted(decisions, key=lambda item: item.timestamp)
        if decision.route_applied and decision.selected_backend in POT_BACKENDS
    ]


def service_events_after(events: list[Event], timestamp: float) -> list[Event]:
    return [event for event in events if event.timestamp >= timestamp]


def has_matching_honeypot_followup(events: list[Event], backend: str, timestamp: float) -> bool:
    for event in service_events_after(events, timestamp):
        app = event.app
        if backend_from_service_event(app) == backend and as_bool(app.get("is_honeypot")):
            return True
    return False


def session_lengths(service_by_session: dict[str, list[Event]]) -> list[float]:
    lengths: list[float] = []
    for rows in service_by_session.values():
        if not rows:
            continue
        lengths.append(max(0.0, rows[-1].timestamp - rows[0].timestamp))
    return lengths


def evaluate_metrics(events: list[Event]) -> dict[str, Any]:
    decisions = collect_decisions(events)
    service_by_session = group_service_events(events)

    decisions_by_session: dict[str, list[RouteDecision]] = defaultdict(list)
    for decision in decisions:
        decisions_by_session[decision.session_id].append(decision)

    all_sessions = set(service_by_session) | set(decisions_by_session)
    attack_sessions = {
        sid
        for sid, rows in decisions_by_session.items()
        if any(decision.is_attack_window for decision in rows)
    }
    benign_sessions = all_sessions - attack_sessions

    first_routes = {
        sid: route
        for sid, rows in decisions_by_session.items()
        if (route := first_applied_route(rows)) is not None
    }
    routed_attack_sessions = {
        sid: route
        for sid, route in first_routes.items()
        if sid in attack_sessions
    }

    engaged_attack_sessions = {
        sid
        for sid, route in routed_attack_sessions.items()
        if has_matching_honeypot_followup(service_by_session.get(sid, []), route.selected_backend, route.timestamp)
    }

    post_route_counts = [
        len(service_events_after(service_by_session.get(sid, []), route.timestamp))
        for sid, route in first_routes.items()
    ]

    correct_decision_count = 0
    correct_outcome_count = 0
    combined_correct_count = 0
    routed_attack_count = len(routed_attack_sessions)
    for sid, route in routed_attack_sessions.items():
        expected = route.expected_backend
        decision_correct = expected in POT_BACKENDS and route.selected_backend == expected
        if route.route_correct_by_semantic_label is not None:
            decision_correct = route.route_correct_by_semantic_label
        outcome_correct = has_matching_honeypot_followup(
            service_by_session.get(sid, []),
            expected,
            route.timestamp,
        ) if expected in POT_BACKENDS else False
        correct_decision_count += int(decision_correct)
        correct_outcome_count += int(outcome_correct)
        combined_correct_count += int(decision_correct and outcome_correct)

    false_rerouted_benign_sessions = {
        sid
        for sid, route in first_routes.items()
        if sid in benign_sessions and route.selected_backend in POT_BACKENDS
    }

    continuity_total = 0
    continuity_ok = 0
    continuity_failures: list[dict[str, Any]] = []
    for sid, session_service_events in service_by_session.items():
        routes = applied_pot_routes(decisions_by_session.get(sid, []))
        if not routes:
            continue

        route_idx = -1
        for event in session_service_events:
            while route_idx + 1 < len(routes) and routes[route_idx + 1].timestamp <= event.timestamp:
                route_idx += 1
            if route_idx < 0:
                continue

            route = routes[route_idx]
            target_surface = BACKEND_TARGET_SURFACE.get(route.selected_backend, "")
            app = event.app
            api_surface = str(app.get("api_surface") or "").strip()
            expected_surface_backend = str(app.get("expected_honeypot_backend") or "").strip()

            # The continuity metric is about every follow-up API surface that
            # is not the target surface of the selected honeypot route. Some
            # normal APIs (health/auth/article list) do not have an expected
            # honeypot backend, but they still count as non-target continuity.
            if api_surface == target_surface or expected_surface_backend == route.selected_backend:
                continue

            continuity_total += 1
            ok = str(app.get("service_role") or "") == "real_service" and backend_from_service_event(app) == NORMAL_BACKEND
            continuity_ok += int(ok)
            if not ok and len(continuity_failures) < 20:
                continuity_failures.append(
                    {
                        "session_id": sid,
                        "route_backend": route.selected_backend,
                        "path": app.get("path"),
                        "api_surface": app.get("api_surface"),
                        "expected_honeypot_backend": expected_surface_backend,
                        "observed_backend": backend_from_service_event(app),
                        "service_role": app.get("service_role"),
                    }
                )

    lengths = session_lengths(service_by_session)
    service_event_count = sum(len(rows) for rows in service_by_session.values())
    honeypot_event_count = sum(
        1
        for rows in service_by_session.values()
        for event in rows
        if as_bool(event.app.get("is_honeypot")) or backend_from_service_event(event.app) in POT_BACKENDS
    )

    return {
        "inputs": {
            "events": len(events),
            "decision_events": len(decisions),
            "service_events": service_event_count,
            "sessions": len(all_sessions),
            "attack_sessions": len(attack_sessions),
            "benign_sessions": len(benign_sessions),
            "routed_sessions": len(first_routes),
            "routed_attack_sessions": routed_attack_count,
        },
        "metric_coverage": {
            "has_llm_decision_fields": any(event_type(event) == "rl_state_decision" for event in events),
            "has_host_service_fields": service_event_count > 0,
            "has_route_match_fields": any(
                "route_matches_api_surface" in event.app
                for rows in service_by_session.values()
                for event in rows
            ),
            "has_expected_backend_fields": any(
                "expected_backend_by_semantic_label" in decision.raw
                for decision in decisions
            ),
        },
        "metrics": {
            "honeypot_engagement_rate": ratio(len(engaged_attack_sessions), routed_attack_count),
            "avg_requests_after_adaptive_rerouting": mean(post_route_counts),
            "session_length_seconds": {
                "avg": mean(lengths),
                "p50": percentile(lengths, 0.50),
                "p95": percentile(lengths, 0.95),
                "max": round(max(lengths), 6) if lengths else None,
            },
            "correct_honeypot_routing_rate": ratio(correct_decision_count, routed_attack_count),
            "correct_honeypot_routing_rate_decision_only": ratio(correct_decision_count, routed_attack_count),
            "correct_honeypot_routing_rate_outcome_only": ratio(correct_outcome_count, routed_attack_count),
            "outcome_verified_correct_routing_rate": ratio(combined_correct_count, routed_attack_count),
            "false_rerouting_rate_on_benign_sessions": ratio(len(false_rerouted_benign_sessions), len(benign_sessions)),
            "normal_service_continuity_rate": ratio(continuity_ok, continuity_total),
        },
        "supporting_counts": {
            "honeypot_service_events": honeypot_event_count,
            "engaged_attack_sessions": len(engaged_attack_sessions),
            "correct_route_decision_attack_sessions": correct_decision_count,
            "outcome_verified_correct_attack_sessions": combined_correct_count,
            "false_rerouted_benign_sessions": len(false_rerouted_benign_sessions),
            "continuity_checked_events": continuity_total,
            "continuity_failures": len(continuity_failures),
        },
        "sample_continuity_failures": continuity_failures,
        "metric_notes": {
            "honeypot_engagement_rate": "routed attack sessions with at least one matching honeypot follow-up / routed attack sessions",
            "avg_requests_after_adaptive_rerouting": "mean host service events after the first applied adaptive route per routed session",
            "session_length_seconds": "duration between first and last host service event per session",
            "correct_honeypot_routing_rate": "selected backend matches semantic expected backend",
            "outcome_verified_correct_routing_rate": "selected backend matches semantic expected backend and matching honeypot outcome appears",
            "false_rerouting_rate_on_benign_sessions": "benign sessions routed to any honeypot / benign sessions observed in host logs",
            "normal_service_continuity_rate": "after a route, every non-target API surface that still hits real_service / all non-target API-surface follow-ups",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate proposal metrics from host-mounted debug logs.")
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS_DIR, help="Host-mounted logs directory.")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path.")
    parser.add_argument("--pretty", action="store_true", help="Print indented JSON.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    events = load_events(args.logs_dir)
    report = evaluate_metrics(events)
    report["logs_dir"] = str(args.logs_dir)
    report["log_files"] = [str(path) for path in iter_log_files(args.logs_dir)]

    text = json.dumps(report, ensure_ascii=True, indent=2 if args.pretty else None)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
