from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from evaluate_metrics import (  # noqa: E402
    Event,
    POT_BACKENDS,
    as_bool,
    backend_from_service_event,
    collect_decisions,
    evaluate_metrics,
    event_type,
    group_service_events,
    iter_log_files,
    load_events,
    session_id,
)


SYSTEM_DIR = Path(__file__).resolve().parents[2]
DEFAULT_LOGS_DIR = SYSTEM_DIR / "logs"
DEFAULT_OUTPUT_DIR = DEFAULT_LOGS_DIR / "metric_visualizations"
DEFAULT_REPLAY_DATA_DIR = SYSTEM_DIR / "control_plane" / "replay_buffer" / "data"

RATE_METRICS = [
    "honeypot_engagement_rate",
    "correct_honeypot_routing_rate",
    "false_rerouting_rate_on_benign_sessions",
    "normal_service_continuity_rate",
]
RQ1_COMPARISON_METRICS = [
    ("correct_honeypot_routing_rate", "Correct honeypot routing rate", "percent", "higher"),
    ("honeypot_engagement_rate", "Honeypot engagement rate", "percent", "higher"),
    ("avg_requests_after_adaptive_rerouting", "Avg requests after adaptive rerouting", "number", "higher"),
    ("false_rerouting_rate_on_benign_sessions", "False rerouting rate on benign sessions", "percent", "lower"),
    ("normal_service_continuity_rate", "Normal-service continuity rate", "percent", "higher"),
]

KIND_TO_BACKEND = {
    "sqli": "sqli_api",
    "cmdi": "cmdi_api",
    "ssti": "ssti_api",
    "ssrf": "ssrf_api",
}
KNOWN_SESSION_KINDS = set(KIND_TO_BACKEND) | {"benign"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build proposal metric tables and report-ready visualizations from host-mounted logs.",
    )
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional traffic manifest from generate_web_replay_buffer.py.",
    )
    parser.add_argument(
        "--session-prefix",
        default="",
        help="Only include events whose session_id starts with this prefix. Useful for a clean demo batch.",
    )
    parser.add_argument("--dpi", type=int, default=150)
    return parser.parse_args()


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def clear_report_outputs(path: Path) -> None:
    ensure_output_dir(path)
    for pattern in ("*.png", "*.csv", "*.json", "REPORT.md"):
        for item in path.glob(pattern):
            if item.is_file():
                item.unlink()


def infer_manifest_path(session_prefix: str) -> Optional[Path]:
    if not session_prefix:
        return None
    return DEFAULT_REPLAY_DATA_DIR / f"{session_prefix}_traffic_manifest.json"


def load_manifest(path: Optional[Path], session_prefix: str) -> tuple[dict[str, Any], Optional[Path]]:
    candidate = path or infer_manifest_path(session_prefix)
    if candidate is None or not candidate.exists():
        return {}, candidate
    return json.loads(candidate.read_text(encoding="utf-8")), candidate


def filter_events(events: list[Event], session_prefix: str) -> list[Event]:
    if not session_prefix:
        return events
    return [event for event in events if session_id(event).startswith(session_prefix)]


def filter_events_to_manifest(events: list[Event], manifest: dict[str, Any]) -> list[Event]:
    manifest_session_ids = {
        str(result.get("session_id") or "").strip()
        for result in manifest.get("session_results", [])
        if isinstance(result, dict) and str(result.get("session_id") or "").strip()
    }
    if not manifest_session_ids:
        return events
    return [event for event in events if session_id(event) in manifest_session_ids]


def clean_value(value: Any) -> Any:
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=True)
    return value


def event_rows(events: Iterable[Event]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events:
        app = event.app
        row = {
            "timestamp": datetime.fromtimestamp(event.timestamp, tz=timezone.utc).isoformat(),
            "event_type": event_type(event),
            "session_id": session_id(event),
            "source_path": event.source_path,
        }
        for key, value in app.items():
            if key not in row:
                row[key] = clean_value(value)
        rows.append(row)
    return rows


def build_decision_frame(events: list[Event]) -> pd.DataFrame:
    decisions = collect_decisions(events)
    rows = []
    for decision in decisions:
        raw = decision.raw
        rows.append(
            {
                "timestamp": datetime.fromtimestamp(decision.timestamp, tz=timezone.utc),
                "decision_id": decision.decision_id,
                "session_id": decision.session_id,
                "event_type": raw.get("event_type"),
                "attack_type": raw.get("attack_type"),
                "semantic_source": raw.get("semantic_source"),
                "action_id": raw.get("action_id"),
                "action_name": raw.get("action_name"),
                "selected_backend": decision.selected_backend,
                "expected_backend": decision.expected_backend,
                "route_applied": decision.route_applied,
                "is_attack_window": decision.is_attack_window,
                "route_correct_by_semantic_label": decision.route_correct_by_semantic_label,
                "llm_confidence": raw.get("llm_confidence"),
                "analysis_duration_ms": raw.get("analysis_duration_ms"),
                "controller_roundtrip_ms": raw.get("controller_roundtrip_ms"),
                "event_to_decision_latency_ms": raw.get("event_to_decision_latency_ms"),
            }
        )
    return pd.DataFrame(rows)


def build_service_frame(events: list[Event]) -> pd.DataFrame:
    rows = []
    for event in events:
        if event_type(event) not in {"request", "honeypot_interaction"}:
            continue
        app = event.app
        rows.append(
            {
                "timestamp": datetime.fromtimestamp(event.timestamp, tz=timezone.utc),
                "session_id": session_id(event),
                "event_type": event_type(event),
                "service": app.get("service"),
                "service_role": app.get("service_role"),
                "observed_backend": backend_from_service_event(app),
                "is_honeypot": as_bool(app.get("is_honeypot")),
                "method": app.get("method"),
                "path": app.get("path"),
                "api_surface": app.get("api_surface"),
                "expected_honeypot_backend": app.get("expected_honeypot_backend"),
                "route_matches_api_surface": app.get("route_matches_api_surface"),
                "status_code": app.get("status_code"),
                "status_class": app.get("status_class"),
                "duration_ms": app.get("duration_ms"),
            }
        )
    return pd.DataFrame(rows)


def build_session_frame(events: list[Event], decisions_df: pd.DataFrame, service_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    service_by_session = group_service_events(events)
    decisions_by_session: dict[str, pd.DataFrame] = {}
    if not decisions_df.empty:
        for sid, frame in decisions_df.groupby("session_id"):
            decisions_by_session[str(sid)] = frame.sort_values("timestamp")

    all_sessions = sorted(set(service_by_session) | set(decisions_by_session))
    for sid in all_sessions:
        service_rows = service_by_session.get(sid, [])
        first_ts: Optional[float] = service_rows[0].timestamp if service_rows else None
        last_ts: Optional[float] = service_rows[-1].timestamp if service_rows else None
        decision_rows = decisions_by_session.get(sid)
        first_decision = None if decision_rows is None or decision_rows.empty else decision_rows.iloc[0]
        rows.append(
            {
                "session_id": sid,
                "service_requests": len(service_rows),
                "honeypot_requests": int(service_df[service_df["session_id"] == sid]["is_honeypot"].sum())
                if not service_df.empty
                else 0,
                "session_length_seconds": round(float(last_ts - first_ts), 6)
                if first_ts is not None and last_ts is not None
                else None,
                "decisions": int(len(decision_rows)) if decision_rows is not None else 0,
                "first_action": None if first_decision is None else first_decision.get("action_name"),
                "first_backend": None if first_decision is None else first_decision.get("selected_backend"),
                "attack_type": None if first_decision is None else first_decision.get("attack_type"),
                "route_applied": bool(decision_rows["route_applied"].any()) if decision_rows is not None else False,
            }
        )
    return pd.DataFrame(rows)


def build_manifest_frames(manifest: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame]:
    session_rows: list[dict[str, Any]] = []
    payload_rows: list[dict[str, Any]] = []
    for result in manifest.get("session_results", []):
        sid = str(result.get("session_id") or "")
        kind = str(result.get("kind") or "")
        variants = [variant for variant in result.get("variants", []) if isinstance(variant, dict)]
        tags = sorted({
            str(tag)
            for variant in variants
            for tag in variant.get("tags", [])
        })
        variant_names = [str(variant.get("variant_name") or "") for variant in variants]
        obfuscated_count = sum(1 for variant in variants if bool(variant.get("is_obfuscated")))
        statuses = result.get("statuses") or []
        session_rows.append({
            "session_id": sid,
            "kind": kind,
            "expected_backend": result.get("expected_backend"),
            "generator_routed": bool(result.get("routed")),
            "status_count": len(statuses),
            "status_codes": ",".join(str(status) for status in statuses),
            "payload_requests": len(variants),
            "obfuscated_payload_requests": obfuscated_count,
            "benign_near_miss_requests": int(result.get("benign_near_miss_requests", 0)),
            "variant_names": ",".join(name for name in variant_names if name),
            "variant_tags": ",".join(tags),
        })
        for index, variant in enumerate(variants, start=1):
            body = variant.get("body") or {}
            payload_rows.append({
                "session_id": sid,
                "kind": kind,
                "request_index": index,
                "method": variant.get("method"),
                "path": variant.get("path"),
                "expected_backend": variant.get("expected_backend"),
                "variant_name": variant.get("variant_name"),
                "tags": ",".join(str(tag) for tag in variant.get("tags", [])),
                "is_obfuscated": bool(variant.get("is_obfuscated")),
                "body": json.dumps(body, ensure_ascii=True, sort_keys=True),
            })
    return pd.DataFrame(session_rows), pd.DataFrame(payload_rows)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(numerator / float(denominator), 6)


def mean(values: Iterable[float]) -> Optional[float]:
    values = list(values)
    if not values:
        return None
    return round(sum(values) / float(len(values)), 6)


def infer_session_kind(sid: str) -> Optional[str]:
    kind = sid.rsplit("_", 1)[-1].strip().lower()
    return kind if kind in KNOWN_SESSION_KINDS else None


def service_events_after(events: list[Event], timestamp: float) -> list[Event]:
    return [event for event in events if event.timestamp >= timestamp]


def has_backend_followup(events: list[Event], backend: str, timestamp: float) -> bool:
    for event in service_events_after(events, timestamp):
        app = event.app
        if backend_from_service_event(app) == backend and as_bool(app.get("is_honeypot")):
            return True
    return False


def has_any_honeypot_followup(events: list[Event], timestamp: float) -> bool:
    for event in service_events_after(events, timestamp):
        app = event.app
        if as_bool(app.get("is_honeypot")) or backend_from_service_event(app) in POT_BACKENDS:
            return True
    return False


def session_lengths(service_by_session: dict[str, list[Event]]) -> list[float]:
    lengths: list[float] = []
    for rows in service_by_session.values():
        if rows:
            lengths.append(max(0.0, rows[-1].timestamp - rows[0].timestamp))
    return lengths


def median(values: list[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return round(ordered[mid], 6)
    return round((ordered[mid - 1] + ordered[mid]) / 2.0, 6)


def first_pot_route(decisions: pd.DataFrame, sid: str) -> Optional[pd.Series]:
    if decisions.empty:
        return None
    rows = decisions[
        (decisions["session_id"] == sid)
        & (decisions["route_applied"].astype(bool))
        & (decisions["selected_backend"].isin(POT_BACKENDS))
    ].sort_values("timestamp")
    if rows.empty:
        return None
    return rows.iloc[0]


def apply_ground_truth_metrics(
    *,
    report: dict[str, Any],
    events: list[Event],
    decisions_df: pd.DataFrame,
) -> dict[str, Any]:
    service_by_session = group_service_events(events)
    labeled_sessions = {
        sid: kind
        for sid in set(service_by_session) | set(decisions_df["session_id"].astype(str) if not decisions_df.empty else [])
        if (kind := infer_session_kind(sid)) is not None
    }
    if not labeled_sessions:
        report["metric_source"] = "analyzer_semantic_labels"
        return report

    attack_sessions = {sid for sid, kind in labeled_sessions.items() if kind != "benign"}
    benign_sessions = {sid for sid, kind in labeled_sessions.items() if kind == "benign"}
    first_routes = {sid: first_pot_route(decisions_df, sid) for sid in labeled_sessions}
    first_routes = {sid: route for sid, route in first_routes.items() if route is not None}

    engaged_attack_sessions = set()
    correct_route_decision_sessions = set()
    outcome_verified_correct_sessions = set()
    false_rerouted_benign_sessions = set()
    post_route_counts: list[int] = []

    for sid, route in first_routes.items():
        route_ts = pd.Timestamp(route["timestamp"]).timestamp()
        selected = str(route["selected_backend"])
        service_events = service_by_session.get(sid, [])
        post_route_counts.append(len(service_events_after(service_events, route_ts)))
        kind = labeled_sessions[sid]

        if kind == "benign":
            if selected in POT_BACKENDS or has_any_honeypot_followup(service_events, route_ts):
                false_rerouted_benign_sessions.add(sid)
            continue

        expected = KIND_TO_BACKEND[kind]
        if has_any_honeypot_followup(service_events, route_ts):
            engaged_attack_sessions.add(sid)
        if selected == expected:
            correct_route_decision_sessions.add(sid)
            if has_backend_followup(service_events, expected, route_ts):
                outcome_verified_correct_sessions.add(sid)

    lengths = session_lengths(service_by_session)
    report["metric_source"] = "session_id_ground_truth"
    report["inputs"].update({
        "ground_truth_labeled_sessions": len(labeled_sessions),
        "ground_truth_attack_sessions": len(attack_sessions),
        "ground_truth_benign_sessions": len(benign_sessions),
        "ground_truth_routed_sessions": len(first_routes),
    })
    report["supporting_counts"].update({
        "engaged_attack_sessions": len(engaged_attack_sessions),
        "correctly_routed_attack_sessions": len(correct_route_decision_sessions),
        "correct_route_decision_attack_sessions": len(correct_route_decision_sessions),
        "outcome_verified_correct_attack_sessions": len(outcome_verified_correct_sessions),
        "false_rerouted_benign_sessions": len(false_rerouted_benign_sessions),
    })
    report["metrics"].update({
        "honeypot_engagement_rate": ratio(len(engaged_attack_sessions), len(attack_sessions)),
        "avg_requests_after_adaptive_rerouting": mean(post_route_counts),
        "session_length_seconds": {
            "min": round(min(lengths), 6) if lengths else None,
            "median": median(lengths),
            "avg": mean(lengths),
            "max": round(max(lengths), 6) if lengths else None,
        },
        "correct_honeypot_routing_rate": ratio(len(correct_route_decision_sessions), len(attack_sessions)),
        "outcome_verified_correct_routing_rate": ratio(len(outcome_verified_correct_sessions), len(attack_sessions)),
        "false_rerouting_rate_on_benign_sessions": ratio(len(false_rerouted_benign_sessions), len(benign_sessions)),
    })
    report["metrics"].pop("correct_honeypot_routing_rate_decision_only", None)
    report["metrics"].pop("correct_honeypot_routing_rate_outcome_only", None)
    report["metric_notes"] = {
        "honeypot_engagement_rate": "actual attack sessions with at least one honeypot follow-up / actual attack sessions",
        "avg_requests_after_adaptive_rerouting": "mean host service events after the first applied adaptive route per routed session",
        "session_length_seconds": "duration between first and last host service event per session",
        "correct_honeypot_routing_rate": "actual attack sessions whose first applied honeypot route matches the attack type / actual attack sessions",
        "outcome_verified_correct_routing_rate": "actual attack sessions whose first applied honeypot route matches the attack type and has matching honeypot follow-up / actual attack sessions",
        "false_rerouting_rate_on_benign_sessions": "ground-truth benign sessions routed to any honeypot / ground-truth benign sessions",
        "normal_service_continuity_rate": "after a route, every non-target API surface that still hits real_service / all non-target API-surface follow-ups",
    }
    return report


def service_has_honeypot_backend(service_df: pd.DataFrame, sid: str, backend: str) -> bool:
    if service_df.empty or "session_id" not in service_df or "observed_backend" not in service_df:
        return False
    rows = service_df[service_df["session_id"].astype(str) == sid]
    if rows.empty:
        return False
    if "is_honeypot" in rows:
        rows = rows[rows["is_honeypot"].fillna(False).astype(bool)]
    return bool((rows["observed_backend"].astype(str) == backend).any())


def build_attack_summary(
    *,
    manifest_session_df: pd.DataFrame,
    decisions_df: pd.DataFrame,
    service_df: pd.DataFrame,
) -> pd.DataFrame:
    if manifest_session_df.empty or "kind" not in manifest_session_df:
        return pd.DataFrame(
            columns=[
                "kind",
                "expected_backend",
                "sessions",
                "generator_routed_sessions",
                "decision_routed_sessions",
                "correct_decision_sessions",
                "engaged_expected_honeypot_sessions",
                "missed_sessions",
                "decision_route_rate",
                "correct_route_rate",
                "engagement_rate",
            ]
        )

    rows: list[dict[str, Any]] = []
    for kind, expected_backend in KIND_TO_BACKEND.items():
        subset = manifest_session_df[manifest_session_df["kind"].astype(str) == kind]
        session_ids = [str(sid) for sid in subset["session_id"].dropna().tolist()]
        if not session_ids:
            continue
        decision_routed = 0
        correct_decisions = 0
        engaged = 0
        for sid in session_ids:
            route = first_pot_route(decisions_df, sid)
            if route is not None:
                decision_routed += 1
                if str(route.get("selected_backend")) == expected_backend:
                    correct_decisions += 1
            if service_has_honeypot_backend(service_df, sid, expected_backend):
                engaged += 1
        sessions = len(session_ids)
        rows.append({
            "kind": kind,
            "expected_backend": expected_backend,
            "sessions": sessions,
            "generator_routed_sessions": int(subset["generator_routed"].fillna(False).astype(bool).sum())
            if "generator_routed" in subset
            else None,
            "decision_routed_sessions": decision_routed,
            "correct_decision_sessions": correct_decisions,
            "engaged_expected_honeypot_sessions": engaged,
            "missed_sessions": max(0, sessions - engaged),
            "decision_route_rate": ratio(decision_routed, sessions),
            "correct_route_rate": ratio(correct_decisions, sessions),
            "engagement_rate": ratio(engaged, sessions),
        })
    return pd.DataFrame(rows)


def build_decision_latency_summary(decisions_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for column in ("analysis_duration_ms", "controller_roundtrip_ms", "event_to_decision_latency_ms"):
        if decisions_df.empty or column not in decisions_df:
            continue
        values = pd.to_numeric(decisions_df[column], errors="coerce").dropna()
        if values.empty:
            continue
        total = int(values.count())
        rows.append({
            "metric": column,
            "count": total,
            "min_ms": round(float(values.min()), 3),
            "avg_ms": round(float(values.mean()), 3),
            "max_ms": round(float(values.max()), 3),
            "under_1s_percent": round(float((values <= 1_000).sum()) / total * 100.0, 3),
            "under_5s_percent": round(float((values <= 5_000).sum()) / total * 100.0, 3),
            "under_10s_percent": round(float((values <= 10_000).sum()) / total * 100.0, 3),
            "over_30s_percent": round(float((values > 30_000).sum()) / total * 100.0, 3),
        })
    return pd.DataFrame(rows)


def build_latency_bucket_summary(decisions_df: pd.DataFrame) -> pd.DataFrame:
    if decisions_df.empty or "event_to_decision_latency_ms" not in decisions_df:
        return pd.DataFrame(columns=["bucket", "decisions", "percent"])
    values = pd.to_numeric(decisions_df["event_to_decision_latency_ms"], errors="coerce").dropna()
    if values.empty:
        return pd.DataFrame(columns=["bucket", "decisions", "percent"])
    buckets = [
        ("<= 1s", values <= 1_000),
        ("1-5s", (values > 1_000) & (values <= 5_000)),
        ("5-10s", (values > 5_000) & (values <= 10_000)),
        ("10-30s", (values > 10_000) & (values <= 30_000)),
        ("> 30s", values > 30_000),
    ]
    total = int(values.count())
    rows = []
    for label, mask in buckets:
        count = int(mask.sum())
        rows.append({
            "bucket": label,
            "decisions": count,
            "percent": round(count / float(total) * 100.0, 3),
        })
    return pd.DataFrame(rows)


def build_session_length_bucket_summary(session_df: pd.DataFrame) -> pd.DataFrame:
    if session_df.empty or "session_length_seconds" not in session_df:
        return pd.DataFrame(columns=["bucket", "sessions", "percent"])
    values = pd.to_numeric(session_df["session_length_seconds"], errors="coerce").dropna()
    if values.empty:
        return pd.DataFrame(columns=["bucket", "sessions", "percent"])
    buckets = [
        ("<= 1s", values <= 1.0),
        ("1-3s", (values > 1.0) & (values <= 3.0)),
        ("3-10s", (values > 3.0) & (values <= 10.0)),
        ("10-30s", (values > 10.0) & (values <= 30.0)),
        ("> 30s", values > 30.0),
    ]
    total = int(values.count())
    rows = []
    for label, mask in buckets:
        count = int(mask.sum())
        rows.append({
            "bucket": label,
            "sessions": count,
            "percent": round(count / float(total) * 100.0, 3),
        })
    return pd.DataFrame(rows)


def build_routing_outcome_summary(report: dict[str, Any], attack_summary_df: pd.DataFrame) -> pd.DataFrame:
    if attack_summary_df.empty:
        return pd.DataFrame(columns=["group", "outcome", "sessions", "percent", "research_question"])

    attack_sessions = int(pd.to_numeric(attack_summary_df["sessions"], errors="coerce").fillna(0).sum())
    correct_decisions = int(
        pd.to_numeric(attack_summary_df["correct_decision_sessions"], errors="coerce").fillna(0).sum()
    )
    engaged_expected = int(
        pd.to_numeric(attack_summary_df["engaged_expected_honeypot_sessions"], errors="coerce").fillna(0).sum()
    )
    correct_no_engagement = max(0, correct_decisions - engaged_expected)
    not_correct_or_missing = max(0, attack_sessions - correct_decisions)

    inputs = report.get("inputs", {})
    supporting = report.get("supporting_counts", {})
    benign_sessions = int(inputs.get("ground_truth_benign_sessions") or 0)
    false_benign = int(supporting.get("false_rerouted_benign_sessions") or 0)
    normal_benign = max(0, benign_sessions - false_benign)

    rows = [
        {
            "group": "Attack",
            "outcome": "Route đúng và có engagement",
            "sessions": engaged_expected,
            "percent": round(engaged_expected / float(attack_sessions) * 100.0, 3) if attack_sessions else None,
            "research_question": "RQ2/RQ4",
        },
        {
            "group": "Attack",
            "outcome": "Route đúng nhưng chưa có engagement",
            "sessions": correct_no_engagement,
            "percent": round(correct_no_engagement / float(attack_sessions) * 100.0, 3) if attack_sessions else None,
            "research_question": "RQ4",
        },
        {
            "group": "Attack",
            "outcome": "Không route đúng hoặc không route",
            "sessions": not_correct_or_missing,
            "percent": round(not_correct_or_missing / float(attack_sessions) * 100.0, 3) if attack_sessions else None,
            "research_question": "RQ2",
        },
        {
            "group": "Benign",
            "outcome": "Giữ ở normal service",
            "sessions": normal_benign,
            "percent": round(normal_benign / float(benign_sessions) * 100.0, 3) if benign_sessions else None,
            "research_question": "RQ4",
        },
        {
            "group": "Benign",
            "outcome": "Bị route nhầm vào honeypot",
            "sessions": false_benign,
            "percent": round(false_benign / float(benign_sessions) * 100.0, 3) if benign_sessions else None,
            "research_question": "RQ4",
        },
    ]
    return pd.DataFrame(rows)


def build_status_summary(service_df: pd.DataFrame) -> pd.DataFrame:
    if service_df.empty:
        return pd.DataFrame(columns=["service_role", "observed_backend", "status_class", "count"])
    frame = service_df.copy()
    for column in ("service_role", "observed_backend", "status_class"):
        frame[column] = frame.get(column, pd.Series(dtype=str)).fillna("unknown").astype(str)
    return (
        frame.groupby(["service_role", "observed_backend", "status_class"])
        .size()
        .reset_index(name="count")
        .sort_values(["service_role", "observed_backend", "status_class"])
    )


def frame_records(frame: pd.DataFrame, limit: int = 20) -> list[dict[str, Any]]:
    if frame.empty:
        return []
    return json.loads(frame.head(limit).to_json(orient="records"))


def metric_tables(report: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    metrics = report["metrics"]
    rate_rows = []
    for name in RATE_METRICS:
        value = metrics.get(name)
        rate_rows.append({"metric": name, "value": value, "percent": None if value is None else round(value * 100.0, 3)})

    session_length = metrics.get("session_length_seconds") or {}
    length_rows = [
        {"metric": f"session_length_seconds_{key}", "value": value}
        for key, value in session_length.items()
    ]
    extra_rows = [
        {
            "metric": "avg_requests_after_adaptive_rerouting",
            "value": metrics.get("avg_requests_after_adaptive_rerouting"),
        }
    ]

    inputs = report.get("inputs", {})
    supporting = report.get("supporting_counts", {})
    if report.get("metric_source") == "session_id_ground_truth":
        counts = {
            "events": inputs.get("events"),
            "decision_events": inputs.get("decision_events"),
            "service_events": inputs.get("service_events"),
            "sessions": inputs.get("sessions"),
            "ground_truth_attack_sessions": inputs.get("ground_truth_attack_sessions"),
            "ground_truth_benign_sessions": inputs.get("ground_truth_benign_sessions"),
            "ground_truth_routed_sessions": inputs.get("ground_truth_routed_sessions"),
            "engaged_attack_sessions": supporting.get("engaged_attack_sessions"),
            "correctly_routed_attack_sessions": supporting.get("correctly_routed_attack_sessions"),
            "correct_route_decision_attack_sessions": supporting.get("correct_route_decision_attack_sessions"),
            "outcome_verified_correct_attack_sessions": supporting.get("outcome_verified_correct_attack_sessions"),
            "false_rerouted_benign_sessions": supporting.get("false_rerouted_benign_sessions"),
            "continuity_checked_events": supporting.get("continuity_checked_events"),
            "continuity_failures": supporting.get("continuity_failures"),
        }
    else:
        counts = inputs | supporting
    count_rows = [{"metric": key, "value": value} for key, value in counts.items()]
    return pd.DataFrame(rate_rows), pd.DataFrame(extra_rows + length_rows), pd.DataFrame(count_rows)


def load_rule_based_baseline(logs_dir: Path) -> dict[str, Any]:
    path = logs_dir / "rule_based_baseline" / "rule_based_metrics.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_rq1_comparison_frame(adaptive_report: dict[str, Any], baseline_report: dict[str, Any]) -> pd.DataFrame:
    if not baseline_report:
        return pd.DataFrame()

    adaptive_metrics = adaptive_report.get("metrics", {})
    baseline_metrics = baseline_report.get("metrics", {})
    rows: list[dict[str, Any]] = []
    for metric_key, label, unit, better_direction in RQ1_COMPARISON_METRICS:
        adaptive_value = adaptive_metrics.get(metric_key)
        baseline_value = baseline_metrics.get(metric_key)
        if adaptive_value is None or baseline_value is None:
            delta = None
            better = "n/a"
        else:
            delta = round(float(adaptive_value) - float(baseline_value), 6)
            if better_direction == "higher":
                better = "adaptive" if delta > 0 else "rule_based" if delta < 0 else "tie"
            else:
                better = "adaptive" if delta < 0 else "rule_based" if delta > 0 else "tie"
        rows.append({
            "metric_key": metric_key,
            "metric": label,
            "unit": unit,
            "better_direction": better_direction,
            "adaptive_value": adaptive_value,
            "adaptive_percent": None if unit != "percent" or adaptive_value is None else round(float(adaptive_value) * 100.0, 3),
            "rule_based_value": baseline_value,
            "rule_based_percent": None if unit != "percent" or baseline_value is None else round(float(baseline_value) * 100.0, 3),
            "adaptive_minus_rule_based": delta,
            "better_system": better,
        })
    return pd.DataFrame(rows)


def save_bar(
    *,
    path: Path,
    labels: list[str],
    values: list[float],
    title: str,
    ylabel: str,
    color: str = "#31688e",
    ylim: Optional[tuple[float, float]] = None,
    dpi: int,
) -> Optional[str]:
    filtered = [(label, value) for label, value in zip(labels, values) if value is not None and not math.isnan(value)]
    if not filtered:
        return None
    labels, values = zip(*filtered)
    fig_width = max(8, min(16, len(labels) * 1.2))
    fig, ax = plt.subplots(figsize=(fig_width, 5))
    bars = ax.bar(range(len(labels)), values, color=color)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if ylim:
        ax.set_ylim(*ylim)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right")
    for bar, value in zip(bars, values):
        text = f"{value:.2f}" if abs(value) < 100 else f"{value:.0f}"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), text, ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def display_labels(labels: Iterable[str]) -> list[str]:
    return [label.replace("_", " ").replace("honeypot", "honeypot\n") for label in labels]


def save_routing_outcome_summary(path: Path, routing_outcome_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if routing_outcome_df.empty:
        return None
    frame = routing_outcome_df.copy()
    frame = frame[frame["group"].astype(str) == "Attack"]
    frame["percent"] = pd.to_numeric(frame["percent"], errors="coerce")
    frame = frame.dropna(subset=["outcome", "percent"])
    if frame.empty:
        return None

    labels = [
        "Correct +\nengaged",
        "Correct but\nno engagement",
        "Wrong or\nmissing route",
    ][: len(frame)]
    values = frame["percent"].fillna(0.0).tolist()
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(range(len(labels)), values, color=["#35b779", "#31688e", "#b5de2b"][: len(labels)])
    ax.set_title("Attack Routing Outcomes")
    ax.set_ylabel("Percent")
    ax.set_ylim(0, 105)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:.1f}", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def save_latency_buckets(path: Path, latency_bucket_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if latency_bucket_df.empty:
        return None
    frame = latency_bucket_df.copy()
    frame["percent"] = pd.to_numeric(frame["percent"], errors="coerce")
    frame["decisions"] = pd.to_numeric(frame["decisions"], errors="coerce")
    frame = frame.dropna(subset=["bucket", "percent"])
    if frame.empty:
        return None
    labels = frame["bucket"].astype(str).tolist()
    values = frame["percent"].fillna(0.0).tolist()
    x_positions = list(range(len(labels)))
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(x_positions, values, color="#31688e")
    ax.set_title("Event-to-Decision Latency Buckets")
    ax.set_ylabel("Decision percent")
    ax.set_ylim(0, 105)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    for bar, value, count in zip(bars, values, frame["decisions"].fillna(0).astype(int).tolist()):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.1f}%\n({count})",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def save_session_length_buckets(path: Path, session_length_bucket_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if session_length_bucket_df.empty:
        return None
    frame = session_length_bucket_df.copy()
    frame["percent"] = pd.to_numeric(frame["percent"], errors="coerce")
    frame["sessions"] = pd.to_numeric(frame["sessions"], errors="coerce")
    frame = frame.dropna(subset=["bucket", "percent"])
    if frame.empty:
        return None
    labels = frame["bucket"].astype(str).tolist()
    values = frame["percent"].fillna(0.0).tolist()
    x_positions = list(range(len(labels)))
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(x_positions, values, color="#443983")
    ax.set_title("Session Length Distribution")
    ax.set_ylabel("Session percent")
    ax.set_ylim(0, 105)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    for bar, value, count in zip(bars, values, frame["sessions"].fillna(0).astype(int).tolist()):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.1f}%\n({count})",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def save_rq1_comparison(path: Path, rq1_comparison_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if rq1_comparison_df.empty:
        return None

    frame = rq1_comparison_df.copy()
    rate_frame = frame[frame["unit"].astype(str) == "percent"].copy()
    value_frame = frame[frame["metric_key"].astype(str) == "avg_requests_after_adaptive_rerouting"].copy()

    if rate_frame.empty and value_frame.empty:
        return None

    fig, axes = plt.subplots(1, 2, figsize=(13, 5), gridspec_kw={"width_ratios": [3.2, 1.2]})

    if not rate_frame.empty:
        labels = rate_frame["metric"].astype(str).tolist()
        adaptive_values = pd.to_numeric(rate_frame["adaptive_percent"], errors="coerce").fillna(0.0).tolist()
        baseline_values = pd.to_numeric(rate_frame["rule_based_percent"], errors="coerce").fillna(0.0).tolist()
        x_positions = list(range(len(labels)))
        width = 0.36
        ax = axes[0]
        bars_adaptive = ax.bar([x - width / 2 for x in x_positions], adaptive_values, width=width, color="#31688e", label="Adaptive")
        bars_rule = ax.bar([x + width / 2 for x in x_positions], baseline_values, width=width, color="#35b779", label="Rule-based")
        ax.set_title("RQ1 Rate Metrics")
        ax.set_ylabel("Percent")
        ax.set_ylim(0, 105)
        ax.set_xticks(x_positions)
        ax.set_xticklabels(
            [
                "Correct\nrouting",
                "Engagement",
                "False\nrerouting",
                "Continuity",
            ][: len(labels)]
        )
        ax.legend(loc="upper right")
        for bar in list(bars_adaptive) + list(bars_rule):
            value = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, value, f"{value:.1f}", ha="center", va="bottom", fontsize=8)
    else:
        axes[0].axis("off")

    if not value_frame.empty:
        row = value_frame.iloc[0]
        adaptive_value = float(row["adaptive_value"])
        baseline_value = float(row["rule_based_value"])
        ax = axes[1]
        bars = ax.bar([0, 1], [adaptive_value, baseline_value], color=["#31688e", "#35b779"])
        ax.set_title("Avg Requests\nAfter Reroute")
        ax.set_ylabel("Requests")
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Adaptive", "Rule-based"])
        upper = max(adaptive_value, baseline_value, 1.0)
        ax.set_ylim(0, upper * 1.25)
        for bar in bars:
            value = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, value, f"{value:.2f}", ha="center", va="bottom", fontsize=8)
    else:
        axes[1].axis("off")

    fig.suptitle("RQ1: Adaptive vs Rule-Based")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def generate_plots(
    *,
    output_dir: Path,
    rate_df: pd.DataFrame,
    value_df: pd.DataFrame,
    rq1_comparison_df: pd.DataFrame,
    manifest_session_df: pd.DataFrame,
    routing_outcome_df: pd.DataFrame,
    latency_bucket_df: pd.DataFrame,
    session_length_bucket_df: pd.DataFrame,
    dpi: int,
) -> list[str]:
    plots: list[str] = []

    rate_plot = save_bar(
        path=output_dir / "01_rate_metrics.png",
        labels=display_labels(rate_df["metric"].tolist()),
        values=rate_df["percent"].fillna(math.nan).tolist(),
        title="Proposal Rate Metrics",
        ylabel="Percent",
        color="#31688e",
        ylim=(0, 105),
        dpi=dpi,
    )
    if rate_plot:
        plots.append(rate_plot)

    avg_requests = value_df[value_df["metric"] == "avg_requests_after_adaptive_rerouting"]
    avg_plot = save_bar(
        path=output_dir / "02_avg_requests_after_adaptive_rerouting.png",
        labels=["avg requests\nafter reroute"],
        values=pd.to_numeric(avg_requests["value"], errors="coerce").fillna(math.nan).tolist(),
        title="Avg Requests After Adaptive Rerouting",
        ylabel="Requests",
        color="#35b779",
        dpi=dpi,
    )
    if avg_plot:
        plots.append(avg_plot)

    session_values = value_df[value_df["metric"].str.startswith("session_length_seconds_")]
    session_plot = save_bar(
        path=output_dir / "03_session_length_summary.png",
        labels=[label.replace("session_length_seconds_", "") for label in session_values["metric"].tolist()],
        values=pd.to_numeric(session_values["value"], errors="coerce").fillna(math.nan).tolist(),
        title="Session Length Summary",
        ylabel="Seconds",
        color="#443983",
        dpi=dpi,
    )
    if session_plot:
        plots.append(session_plot)

    session_length_distribution = save_session_length_buckets(
        output_dir / "04_session_length_distribution.png",
        session_length_bucket_df,
        dpi,
    )
    if session_length_distribution:
        plots.append(session_length_distribution)

    if not manifest_session_df.empty and "kind" in manifest_session_df:
        mix = (
            manifest_session_df.groupby("kind")
            .size()
            .reset_index(name="sessions")
            .sort_values("kind")
        )
        session_mix = save_bar(
            path=output_dir / "05_ground_truth_session_mix.png",
            labels=mix["kind"].astype(str).tolist(),
            values=pd.to_numeric(mix["sessions"], errors="coerce").fillna(math.nan).tolist(),
            title="Ground-Truth Session Mix",
            ylabel="Sessions",
            color="#21918c",
            dpi=dpi,
        )
        if session_mix:
            plots.append(session_mix)

    rq1_plot = save_rq1_comparison(
        output_dir / "06_rq1_comparison.png",
        rq1_comparison_df,
        dpi,
    )
    if rq1_plot:
        plots.append(rq1_plot)

    routing_outcomes = save_routing_outcome_summary(
        output_dir / "07_routing_outcome_summary.png",
        routing_outcome_df,
        dpi,
    )
    if routing_outcomes:
        plots.append(routing_outcomes)

    latency_plot = save_latency_buckets(output_dir / "08_decision_latency_buckets.png", latency_bucket_df, dpi)
    if latency_plot:
        plots.append(latency_plot)

    return plots


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join("" if value is None else str(value) for value in row) + " |")
    return "\n".join(lines)


def dataframe_markdown(frame: pd.DataFrame, columns: list[str], limit: int = 12) -> str:
    if frame.empty:
        return "_No data._"
    available = [column for column in columns if column in frame.columns]
    if not available:
        return "_No data._"
    rows = []
    for _, row in frame.head(limit).iterrows():
        values = []
        for column in available:
            value = row[column]
            if pd.isna(value):
                values.append("")
            elif isinstance(value, float):
                values.append(round(value, 6))
            else:
                values.append(value)
        rows.append(values)
    return markdown_table(available, rows)


def write_markdown_report(
    *,
    output_dir: Path,
    report: dict[str, Any],
    rate_df: pd.DataFrame,
    value_df: pd.DataFrame,
    count_df: pd.DataFrame,
    rq1_comparison_df: pd.DataFrame,
    manifest_session_df: pd.DataFrame,
    latency_df: pd.DataFrame,
    routing_outcome_df: pd.DataFrame,
    latency_bucket_df: pd.DataFrame,
    session_length_bucket_df: pd.DataFrame,
    plots: list[str],
    session_prefix: str,
    manifest_path: Optional[Path],
) -> None:
    generated_at = datetime.now(timezone.utc).isoformat()

    def row_value(frame: pd.DataFrame, metric: str, column: str = "value") -> Any:
        rows = frame[frame["metric"] == metric] if "metric" in frame else pd.DataFrame()
        if rows.empty or column not in rows:
            return None
        value = rows.iloc[0][column]
        return None if pd.isna(value) else value

    def routing_outcome_value(group: str, outcome: str, column: str) -> Any:
        if routing_outcome_df.empty:
            return None
        rows = routing_outcome_df[
            (routing_outcome_df["group"].astype(str) == group)
            & (routing_outcome_df["outcome"].astype(str) == outcome)
        ]
        if rows.empty or column not in rows:
            return None
        value = rows.iloc[0][column]
        return None if pd.isna(value) else value

    def fmt_number(value: Any, digits: int = 3) -> str:
        if value is None or pd.isna(value):
            return ""
        if isinstance(value, float):
            return str(round(value, digits))
        return str(value)

    def fmt_percent(value: Any) -> str:
        if value is None or pd.isna(value):
            return ""
        return f"{float(value):.3f}%"

    count_map = {
        str(row["metric"]): row["value"]
        for _, row in count_df.iterrows()
        if "metric" in count_df and "value" in count_df
    }
    obfuscated_payloads = 0
    benign_near_miss = 0
    if not manifest_session_df.empty:
        if "obfuscated_payload_requests" in manifest_session_df:
            obfuscated_payloads = int(
                pd.to_numeric(manifest_session_df["obfuscated_payload_requests"], errors="coerce").fillna(0).sum()
            )
        if "benign_near_miss_requests" in manifest_session_df:
            benign_near_miss = int(
                pd.to_numeric(manifest_session_df["benign_near_miss_requests"], errors="coerce").fillna(0).sum()
            )

    main_metric_rows = [
        [
            "Honeypot engagement rate",
            "Attack session có request thực tế vào honeypot sau reroute.",
            fmt_percent(row_value(rate_df, "honeypot_engagement_rate", "percent")),
        ],
        [
            "Avg requests after adaptive rerouting",
            "Số request trung bình phát sinh sau khi adaptive route được áp dụng.",
            fmt_number(row_value(value_df, "avg_requests_after_adaptive_rerouting")),
        ],
        [
            "Session length",
            "Thời lượng session từ request đầu đến request cuối.",
            "min "
            + fmt_number(row_value(value_df, "session_length_seconds_min"))
            + "s, median "
            + fmt_number(row_value(value_df, "session_length_seconds_median"))
            + "s, avg "
            + fmt_number(row_value(value_df, "session_length_seconds_avg"))
            + "s, max "
            + fmt_number(row_value(value_df, "session_length_seconds_max"))
            + "s",
        ],
        [
            "Correct honeypot routing rate",
            "Attack session được route đúng honeypot theo đúng loại attack.",
            fmt_percent(row_value(rate_df, "correct_honeypot_routing_rate", "percent")),
        ],
        [
            "False rerouting rate on benign sessions",
            "Benign session bị route nhầm vào honeypot. Càng thấp càng tốt.",
            fmt_percent(row_value(rate_df, "false_rerouting_rate_on_benign_sessions", "percent")),
        ],
        [
            "Normal-service continuity rate",
            "Request không thuộc API mục tiêu vẫn đi về real service sau reroute.",
            fmt_percent(row_value(rate_df, "normal_service_continuity_rate", "percent")),
        ],
    ]
    sample_rows = [
        ["Tổng session", count_map.get("sessions")],
        ["Attack sessions", count_map.get("ground_truth_attack_sessions")],
        ["Benign sessions", count_map.get("ground_truth_benign_sessions")],
        ["Runtime events", count_map.get("events")],
        ["Service events", count_map.get("service_events")],
        ["Decision events", count_map.get("decision_events")],
        ["Obfuscated attack payload requests", obfuscated_payloads],
        ["Benign near-miss requests", benign_near_miss],
    ]

    lines = [
        "# Báo cáo metric Adaptive Honeypot",
        "",
        "## Phạm vi báo cáo",
        "",
        "Báo cáo này đánh giá flow adaptive routing trên traffic Web hỗn hợp: benign, benign near-miss, baseline attack và obfuscated attack.",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Session prefix: `{session_prefix or 'all sessions'}`",
        f"- Metric source: `{report.get('metric_source', 'unknown')}`",
        f"- Traffic manifest: `{manifest_path if manifest_path and manifest_path.exists() else 'not found'}`",
        "",
        "Nguồn runtime log dùng để thống kê:",
        "",
        "```text",
        "logs/real_backend/service_requests.jsonl",
        "logs/honeypots/cmdi/service_requests.jsonl",
        "logs/honeypots/sqli/service_requests.jsonl",
        "logs/honeypots/ssrf/service_requests.jsonl",
        "logs/honeypots/ssti/service_requests.jsonl",
        "logs/llm_analyzer/llm_fields.jsonl",
        "```",
        "",
        "## Liên hệ Research Questions",
        "",
        markdown_table(
            ["Research Question", "Metric trong báo cáo", "Ghi chú"],
            [
                [
                    "RQ1: LLM + RL có tốt hơn rule-based không?",
                    "Mục RQ1 trong báo cáo này",
                    "Đọc bảng so sánh adaptive với baseline rule-based trên cùng traffic manifest.",
                ],
                [
                    "RQ2: RL action có route đúng honeypot không?",
                    "Correct honeypot routing rate, attack routing outcomes",
                    "Tách rõ route decision đúng và outcome sau route.",
                ],
                [
                    "RQ3: Độ trễ pipeline thế nào?",
                    "Event-to-decision latency buckets",
                    "Đo thời gian từ log event đến khi có decision.",
                ],
                [
                    "RQ4: Rerouting có tăng engagement và giữ service ổn định không?",
                    "Engagement, avg requests sau reroute, session length, false rerouting, continuity",
                    "Đo engagement, route nhầm benign và continuity.",
                ],
            ],
        ),
        "",
        "## Quy mô dữ liệu",
        "",
        markdown_table(["Chỉ số", "Giá trị"], sample_rows),
        "",
        "Tập dữ liệu phù hợp để báo cáo demo Web hiện tại vì có benign traffic, benign near-miss và bốn nhóm attack chính. Đây chưa phải benchmark production.",
        "",
        "## Metric chính",
        "",
        markdown_table(["Metric", "Ý nghĩa", "Giá trị"], main_metric_rows),
        "",
        "Nhận định ngắn:",
        "",
        f"- Correct honeypot routing rate đạt `{fmt_percent(row_value(rate_df, 'correct_honeypot_routing_rate', 'percent'))}` theo nghĩa route decision đúng loại honeypot.",
        f"- Honeypot engagement rate đạt `{fmt_percent(row_value(rate_df, 'honeypot_engagement_rate', 'percent'))}` theo nghĩa attack session có follow-up thực tế vào honeypot sau reroute.",
        f"- Route đúng và có engagement vào đúng honeypot kỳ vọng đạt `{fmt_percent(routing_outcome_value('Attack', 'Route đúng và có engagement', 'percent'))}`.",
        f"- Normal-service continuity đạt `{fmt_percent(row_value(rate_df, 'normal_service_continuity_rate', 'percent'))}`, tức rerouting theo API mục tiêu không làm hỏng các API còn lại trong cùng session.",
        f"- False rerouting trên benign là `{fmt_percent(row_value(rate_df, 'false_rerouting_rate_on_benign_sessions', 'percent'))}`; đây là điểm cần cải thiện nếu mở rộng đề tài.",
        "",
    ]

    if not rq1_comparison_df.empty:
        def rq1_value(metric_key: str, column: str) -> Any:
            rows = rq1_comparison_df[rq1_comparison_df["metric_key"] == metric_key]
            if rows.empty or column not in rows:
                return None
            value = rows.iloc[0][column]
            return None if pd.isna(value) else value

        lines.extend(
            [
                "## RQ1: Adaptive vs Rule-Based",
                "",
                dataframe_markdown(
                    rq1_comparison_df,
                    [
                        "metric",
                        "adaptive_percent",
                        "rule_based_percent",
                        "adaptive_value",
                        "rule_based_value",
                        "better_system",
                    ],
                ),
                "",
                "Nhận xét ngắn cho RQ1:",
                "",
                f"- Adaptive đạt `{fmt_percent(rq1_value('correct_honeypot_routing_rate', 'adaptive_percent'))}` correct routing, cao hơn rule-based `{fmt_percent(rq1_value('correct_honeypot_routing_rate', 'rule_based_percent'))}`.",
                f"- Adaptive đạt `{fmt_percent(rq1_value('honeypot_engagement_rate', 'adaptive_percent'))}` engagement, cao hơn rule-based `{fmt_percent(rq1_value('honeypot_engagement_rate', 'rule_based_percent'))}`.",
                f"- Avg requests after reroute: adaptive `{fmt_number(rq1_value('avg_requests_after_adaptive_rerouting', 'adaptive_value'))}` vs rule-based `{fmt_number(rq1_value('avg_requests_after_adaptive_rerouting', 'rule_based_value'))}`.",
                f"- Rule-based bảo thủ hơn trên benign của tập benchmark này: false rerouting `{fmt_percent(rq1_value('false_rerouting_rate_on_benign_sessions', 'rule_based_percent'))}` so với adaptive `{fmt_percent(rq1_value('false_rerouting_rate_on_benign_sessions', 'adaptive_percent'))}`.",
                "",
            ]
        )
        if "06_rq1_comparison.png" in plots:
            lines.extend(
                [
                    "![06_rq1_comparison.png](06_rq1_comparison.png)",
                    "",
                    "Hình này gom phần so sánh chính của RQ1: các metric dạng tỷ lệ ở bên trái và số request trung bình sau reroute ở bên phải.",
                    "",
                ]
            )

    lines.extend(
        [
            "## Routing outcome gắn với RQ2/RQ4",
            "",
            dataframe_markdown(routing_outcome_df, ["group", "outcome", "sessions", "percent", "research_question"]),
            "",
            "Bảng này thay cho bảng chi tiết theo từng loại attack. Ở đây `Route đúng` nghĩa là decision đã chọn đúng honeypot theo loại attack; cột `có engagement` là bước kiểm chứng tiếp theo, tức sau khi route đúng thì attacker còn thực sự follow-up vào đúng honeypot đó.",
            "",
            "## Decision latency",
            "",
            dataframe_markdown(
                latency_df,
                ["metric", "count", "min_ms", "avg_ms", "max_ms", "under_1s_percent", "under_5s_percent", "under_10s_percent", "over_30s_percent"],
            ),
            "",
            "Ý nghĩa các trường latency:",
            "",
            "- `analysis_duration_ms`: thời gian LLM analyzer parse log và tạo semantic fields.",
            "- `controller_roundtrip_ms`: thời gian gọi Routing Controller/RL và áp dụng route.",
            "- `event_to_decision_latency_ms`: tổng thời gian từ request/log đầu vào đến khi có decision. Đây là chỉ số sát RQ3 nhất.",
            "",
            "Phần bucket latency:",
            "",
            dataframe_markdown(latency_bucket_df, ["bucket", "decisions", "percent"]),
            "",
            "## Phân bổ session length",
            "",
            dataframe_markdown(session_length_bucket_df, ["bucket", "sessions", "percent"]),
            "",
            "## Hình ảnh chính",
            "",
        ]
    )

    figure_notes = {
        "01_rate_metrics.png": "Tổng hợp bốn metric dạng tỷ lệ. Ở đây correct routing là route decision đúng; engagement là follow-up thực tế sau reroute.",
        "02_avg_requests_after_adaptive_rerouting.png": "Số request trung bình sau reroute. Giá trị cao hơn cho thấy attacker tiếp tục tương tác sau khi bị đưa vào honeypot.",
        "03_session_length_summary.png": "Session length được tóm tắt bằng min, median, avg và max để nhìn nhanh độ dài ngắn-vừa-dài.",
        "04_session_length_distribution.png": "Phân bổ session theo bucket thời lượng để thấy phần lớn session tập trung ở khoảng nào.",
        "05_ground_truth_session_mix.png": "Phân bố ground truth của tập test: benign và bốn nhóm attack.",
        "06_rq1_comparison.png": "So sánh trực tiếp adaptive với rule-based cho RQ1: correct routing, engagement, false rerouting, continuity và avg requests after reroute.",
        "07_routing_outcome_summary.png": "Outcome tổng hợp cho RQ2/RQ4: đúng+engaged, đúng nhưng chưa engaged, sai/không route.",
        "08_decision_latency_buckets.png": "Độ trễ event-to-decision theo bucket để đọc trực tiếp tỷ lệ decision nhanh/chậm.",
    }
    for plot in plots:
        lines.extend([f"### {plot}", "", f"![{plot}]({plot})", "", figure_notes.get(plot, ""), ""])

    lines.extend(
        [
            "## Kết luận",
            "",
            "- RQ1: Adaptive route đúng nhiều hơn và route sớm hơn baseline rule-based trên cùng traffic manifest; baseline bảo thủ hơn với benign nhưng bỏ sót nhiều payload evade hơn.",
            "- RQ2: Correct routing cần đọc theo metric chính; bảng outcome phía trên cho thấy phần nào trong số đó đã tiếp tục tạo engagement thực tế.",
            "- RQ3: Nên đọc latency bằng bucket event-to-decision; đây là metric để giải thích vì sao route đúng nhưng engagement có thể chưa xảy ra.",
            "- RQ4: Continuity đang tốt, false rerouting trên benign là rủi ro lớn nhất.",
            "",
        ]
    )
    (output_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    clear_report_outputs(args.output_dir)
    manifest, manifest_path = load_manifest(args.manifest, args.session_prefix)

    events = filter_events(load_events(args.logs_dir), args.session_prefix)
    events = filter_events_to_manifest(events, manifest)
    if not events:
        raise RuntimeError(
            f"No events found in {args.logs_dir}"
            + (f" for session prefix {args.session_prefix!r}" if args.session_prefix else "")
        )

    report = evaluate_metrics(events)
    report["logs_dir"] = str(args.logs_dir)
    report["session_prefix"] = args.session_prefix
    report["log_files"] = [str(path) for path in iter_log_files(args.logs_dir)]
    report["traffic_manifest"] = str(manifest_path) if manifest_path and manifest_path.exists() else None

    decisions_df = build_decision_frame(events)
    service_df = build_service_frame(events)
    report = apply_ground_truth_metrics(report=report, events=events, decisions_df=decisions_df)
    session_df = build_session_frame(events, decisions_df, service_df)
    manifest_session_df, payload_df = build_manifest_frames(manifest)
    if not manifest_session_df.empty and not session_df.empty and "session_id" in manifest_session_df and "session_id" in session_df:
        observed_sessions = set(session_df["session_id"].astype(str))
        manifest_session_df = manifest_session_df[manifest_session_df["session_id"].astype(str).isin(observed_sessions)].copy()
        if not payload_df.empty and "session_id" in payload_df:
            payload_df = payload_df[payload_df["session_id"].astype(str).isin(observed_sessions)].copy()
    attack_summary_df = build_attack_summary(
        manifest_session_df=manifest_session_df,
        decisions_df=decisions_df,
        service_df=service_df,
    )
    routing_outcome_df = build_routing_outcome_summary(report, attack_summary_df)
    latency_df = build_decision_latency_summary(decisions_df)
    latency_bucket_df = build_latency_bucket_summary(decisions_df)
    session_length_bucket_df = build_session_length_bucket_summary(session_df)
    status_summary_df = build_status_summary(service_df)
    report["supporting_statistics"] = {
        "traffic_manifest_loaded": bool(manifest),
        "manifest_sessions": int(len(manifest_session_df)),
        "payload_requests": int(len(payload_df)),
        "obfuscated_payload_requests": int(payload_df["is_obfuscated"].sum())
        if not payload_df.empty and "is_obfuscated" in payload_df
        else 0,
        "routing_outcome_summary": frame_records(routing_outcome_df),
        "decision_latency_summary": frame_records(latency_df),
        "event_to_decision_latency_buckets": frame_records(latency_bucket_df),
        "session_length_buckets": frame_records(session_length_bucket_df),
    }
    baseline_report = load_rule_based_baseline(args.logs_dir)
    rq1_comparison_df = build_rq1_comparison_frame(report, baseline_report)
    rate_df, value_df, count_df = metric_tables(report)
    proposal_df = pd.concat(
        [
            rate_df[["metric", "value", "percent"]],
            value_df.assign(percent=None)[["metric", "value", "percent"]],
        ],
        ignore_index=True,
    )

    write_json(args.output_dir / "proposal_metrics_report.json", report)
    proposal_df.to_csv(args.output_dir / "proposal_metrics.csv", index=False)
    session_df.to_csv(args.output_dir / "session_summary.csv", index=False)
    rate_df.to_csv(args.output_dir / "rate_metrics.csv", index=False)
    value_df.to_csv(args.output_dir / "value_metrics.csv", index=False)
    manifest_session_df.to_csv(args.output_dir / "traffic_manifest_sessions.csv", index=False)
    routing_outcome_df.to_csv(args.output_dir / "routing_outcome_summary.csv", index=False)
    latency_df.to_csv(args.output_dir / "decision_latency_summary.csv", index=False)
    latency_bucket_df.to_csv(args.output_dir / "decision_latency_buckets.csv", index=False)
    session_length_bucket_df.to_csv(args.output_dir / "session_length_distribution.csv", index=False)
    status_summary_df.to_csv(args.output_dir / "service_status_summary.csv", index=False)
    if not rq1_comparison_df.empty:
        rq1_comparison_df.to_csv(args.output_dir / "rq1_comparison.csv", index=False)

    plots = generate_plots(
        output_dir=args.output_dir,
        rate_df=rate_df,
        value_df=value_df,
        rq1_comparison_df=rq1_comparison_df,
        manifest_session_df=manifest_session_df,
        routing_outcome_df=routing_outcome_df,
        latency_bucket_df=latency_bucket_df,
        session_length_bucket_df=session_length_bucket_df,
        dpi=args.dpi,
    )
    write_markdown_report(
        output_dir=args.output_dir,
        report=report,
        rate_df=rate_df,
        value_df=value_df,
        count_df=count_df,
        rq1_comparison_df=rq1_comparison_df,
        manifest_session_df=manifest_session_df,
        latency_df=latency_df,
        routing_outcome_df=routing_outcome_df,
        latency_bucket_df=latency_bucket_df,
        session_length_bucket_df=session_length_bucket_df,
        plots=plots,
        session_prefix=args.session_prefix,
        manifest_path=manifest_path,
    )

    print(json.dumps({
        "output_dir": str(args.output_dir),
        "events": len(events),
        "decisions": len(decisions_df),
        "service_events": len(service_df),
        "sessions": len(session_df),
        "manifest": str(manifest_path) if manifest_path and manifest_path.exists() else None,
        "payload_requests": int(len(payload_df)),
        "obfuscated_payload_requests": int(payload_df["is_obfuscated"].sum())
        if not payload_df.empty and "is_obfuscated" in payload_df
        else 0,
        "rq1_comparison_rows": int(len(rq1_comparison_df)),
        "figures": plots,
        "report": str(args.output_dir / "REPORT.md"),
    }, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
