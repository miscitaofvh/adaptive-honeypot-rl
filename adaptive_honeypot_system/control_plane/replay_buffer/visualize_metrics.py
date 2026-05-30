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

RATE_METRICS = [
    "honeypot_engagement_rate",
    "correct_honeypot_routing_rate",
    "false_rerouting_rate_on_benign_sessions",
    "normal_service_continuity_rate",
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


def filter_events(events: list[Event], session_prefix: str) -> list[Event]:
    if not session_prefix:
        return events
    return [event for event in events if session_id(event).startswith(session_prefix)]


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
    correct_attack_sessions = set()
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
        if selected == expected and has_backend_followup(service_events, expected, route_ts):
            correct_attack_sessions.add(sid)

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
        "correctly_routed_attack_sessions": len(correct_attack_sessions),
        "false_rerouted_benign_sessions": len(false_rerouted_benign_sessions),
    })
    report["metrics"].update({
        "honeypot_engagement_rate": ratio(len(engaged_attack_sessions), len(attack_sessions)),
        "avg_requests_after_adaptive_rerouting": mean(post_route_counts),
        "session_length_seconds": {
            "avg": mean(lengths),
            "p50": percentile(lengths, 0.50),
            "p95": percentile(lengths, 0.95),
            "max": round(max(lengths), 6) if lengths else None,
        },
        "correct_honeypot_routing_rate": ratio(len(correct_attack_sessions), len(attack_sessions)),
        "false_rerouting_rate_on_benign_sessions": ratio(len(false_rerouted_benign_sessions), len(benign_sessions)),
    })
    report["metrics"].pop("correct_honeypot_routing_rate_decision_only", None)
    report["metrics"].pop("correct_honeypot_routing_rate_outcome_only", None)
    report["metric_notes"] = {
        "honeypot_engagement_rate": "actual attack sessions with at least one honeypot follow-up / actual attack sessions",
        "avg_requests_after_adaptive_rerouting": "mean host service events after the first applied adaptive route per routed session",
        "session_length_seconds": "duration between first and last host service event per session",
        "correct_honeypot_routing_rate": "actual attack sessions whose first applied honeypot route matches the attack type and has matching honeypot follow-up / actual attack sessions",
        "false_rerouting_rate_on_benign_sessions": "ground-truth benign sessions routed to any honeypot / ground-truth benign sessions",
        "normal_service_continuity_rate": "after a route, every non-target API surface that still hits real_service / all non-target API-surface follow-ups",
    }
    return report


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
            "false_rerouted_benign_sessions": supporting.get("false_rerouted_benign_sessions"),
            "continuity_checked_events": supporting.get("continuity_checked_events"),
            "continuity_failures": supporting.get("continuity_failures"),
        }
    else:
        counts = inputs | supporting
    count_rows = [{"metric": key, "value": value} for key, value in counts.items()]
    return pd.DataFrame(rate_rows), pd.DataFrame(extra_rows + length_rows), pd.DataFrame(count_rows)


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


def save_heatmap(path: Path, frame: pd.DataFrame, dpi: int) -> Optional[str]:
    if frame.empty or "expected_backend" not in frame or "selected_backend" not in frame:
        return None
    rows = frame[frame["expected_backend"].isin(POT_BACKENDS)]
    if rows.empty:
        return None
    matrix = pd.crosstab(rows["expected_backend"], rows["selected_backend"])
    if matrix.empty:
        return None

    fig, ax = plt.subplots(figsize=(8, 6))
    image = ax.imshow(matrix.values, cmap="Blues")
    ax.set_title("Expected vs Selected Honeypot Backend")
    ax.set_xlabel("Selected backend")
    ax.set_ylabel("Expected backend")
    ax.set_xticks(range(len(matrix.columns)))
    ax.set_xticklabels(matrix.columns, rotation=30, ha="right")
    ax.set_yticks(range(len(matrix.index)))
    ax.set_yticklabels(matrix.index)
    for i, expected in enumerate(matrix.index):
        for j, selected in enumerate(matrix.columns):
            ax.text(j, i, str(matrix.loc[expected, selected]), ha="center", va="center", color="#111111")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def save_timeline(path: Path, decisions_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if decisions_df.empty or "timestamp" not in decisions_df or "action_name" not in decisions_df:
        return None
    frame = decisions_df.copy()
    frame = frame.dropna(subset=["timestamp"])
    if frame.empty:
        return None
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame = frame.set_index("timestamp")
    counts = frame.groupby("action_name").resample("30s").size().unstack(0).fillna(0)
    if counts.empty:
        return None
    fig, ax = plt.subplots(figsize=(12, 5))
    counts.plot(ax=ax)
    ax.set_title("RL Decisions Over Time")
    ax.set_xlabel("Time")
    ax.set_ylabel("Decision count / 30s")
    ax.legend(title="Action", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def save_histogram(path: Path, session_df: pd.DataFrame, dpi: int) -> Optional[str]:
    if session_df.empty or "session_length_seconds" not in session_df:
        return None
    values = pd.to_numeric(session_df["session_length_seconds"], errors="coerce").dropna()
    if values.empty:
        return None
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(values, bins=min(20, max(5, len(values) // 4)), color="#35b779", edgecolor="white")
    ax.set_title("Session Length Distribution")
    ax.set_xlabel("Seconds")
    ax.set_ylabel("Sessions")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    return path.name


def generate_plots(
    *,
    output_dir: Path,
    rate_df: pd.DataFrame,
    value_df: pd.DataFrame,
    count_df: pd.DataFrame,
    decisions_df: pd.DataFrame,
    service_df: pd.DataFrame,
    session_df: pd.DataFrame,
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

    histogram = save_histogram(output_dir / "04_session_length_distribution.png", session_df, dpi)
    if histogram:
        plots.append(histogram)

    return plots


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join("" if value is None else str(value) for value in row) + " |")
    return "\n".join(lines)


def write_markdown_report(
    *,
    output_dir: Path,
    report: dict[str, Any],
    rate_df: pd.DataFrame,
    value_df: pd.DataFrame,
    count_df: pd.DataFrame,
    plots: list[str],
    session_prefix: str,
) -> None:
    generated_at = datetime.now(timezone.utc).isoformat()
    rate_rows = [
        [row["metric"], "" if pd.isna(row["value"]) else row["value"], "" if pd.isna(row["percent"]) else row["percent"]]
        for _, row in rate_df.iterrows()
    ]
    value_rows = [
        [row["metric"], "" if pd.isna(row["value"]) else row["value"]]
        for _, row in value_df.iterrows()
    ]
    count_rows = [
        [row["metric"], "" if pd.isna(row["value"]) else row["value"]]
        for _, row in count_df.iterrows()
    ]

    lines = [
        "# Adaptive Honeypot Metrics Report",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Session prefix: `{session_prefix or 'all sessions'}`",
        f"- Metric source: `{report.get('metric_source', 'unknown')}`",
        "",
        "## Proposal Rate Metrics",
        "",
        markdown_table(["Metric", "Ratio", "Percent"], rate_rows),
        "",
        "## Proposal Value Metrics",
        "",
        markdown_table(["Metric", "Value"], value_rows),
        "",
        "## Evaluation Sample",
        "",
        markdown_table(["Metric", "Value"], count_rows),
        "",
        "## Coverage",
        "",
        "```json",
        json.dumps(report.get("metric_coverage", {}), ensure_ascii=True, indent=2),
        "```",
        "",
        "## Figures",
        "",
    ]
    for plot in plots:
        lines.extend([f"![{plot}]({plot})", ""])
    lines.extend(
        [
            "## Notes",
            "",
            "- Metrics are computed from host-mounted debug logs.",
            "- Generated replay sessions use the session id suffix as ground truth when available.",
            "- `llm_fields.jsonl` contains RL state/action/backend decision fields.",
            "- Service request logs confirm whether the selected route actually reached the intended honeypot.",
            "",
        ]
    )
    (output_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    clear_report_outputs(args.output_dir)

    events = filter_events(load_events(args.logs_dir), args.session_prefix)
    if not events:
        raise RuntimeError(
            f"No events found in {args.logs_dir}"
            + (f" for session prefix {args.session_prefix!r}" if args.session_prefix else "")
        )

    report = evaluate_metrics(events)
    report["logs_dir"] = str(args.logs_dir)
    report["session_prefix"] = args.session_prefix
    report["log_files"] = [str(path) for path in iter_log_files(args.logs_dir)]

    decisions_df = build_decision_frame(events)
    service_df = build_service_frame(events)
    report = apply_ground_truth_metrics(report=report, events=events, decisions_df=decisions_df)
    session_df = build_session_frame(events, decisions_df, service_df)
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

    plots = generate_plots(
        output_dir=args.output_dir,
        rate_df=rate_df,
        value_df=value_df,
        count_df=count_df,
        decisions_df=decisions_df,
        service_df=service_df,
        session_df=session_df,
        dpi=args.dpi,
    )
    write_markdown_report(
        output_dir=args.output_dir,
        report=report,
        rate_df=rate_df,
        value_df=value_df,
        count_df=count_df,
        plots=plots,
        session_prefix=args.session_prefix,
    )

    print(json.dumps({
        "output_dir": str(args.output_dir),
        "events": len(events),
        "decisions": len(decisions_df),
        "service_events": len(service_df),
        "sessions": len(session_df),
        "figures": plots,
        "report": str(args.output_dir / "REPORT.md"),
    }, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
