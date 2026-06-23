from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


SYSTEM_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    SYSTEM_DIR
    / "control_plane"
    / "replay_buffer"
    / "data"
    / "obf_20260602_combined_traffic_manifest.json"
)
DEFAULT_ADAPTIVE_REPORT = SYSTEM_DIR / "logs" / "metric_visualizations" / "proposal_metrics_report.json"
DEFAULT_OUTPUT_DIR = SYSTEM_DIR / "logs" / "rule_based_baseline"

PATH_TO_BACKEND = {
    "/api/articles/search": "sqli_api",
    "/api/tools/ping": "cmdi_api",
    "/api/tools/preview": "ssti_api",
    "/api/tools/fetch": "ssrf_api",
}
BACKEND_TO_KIND = {
    "sqli_api": "sqli",
    "cmdi_api": "cmdi",
    "ssti_api": "ssti",
    "ssrf_api": "ssrf",
}
POT_BACKENDS = set(BACKEND_TO_KIND)
RULE_ROUTE_THRESHOLD = 1.50
MIN_SIGNAL_HITS = {
    "sqli_api": 4,
    "cmdi_api": 4,
    "ssti_api": 4,
    "ssrf_api": 4,
}
RULE_WEIGHTS = {
    "sqli_api": 0.48,
    "cmdi_api": 0.42,
    "ssti_api": 0.36,
    "ssrf_api": 0.42,
}
WEAK_CONTEXT_SIGNAL_THRESHOLD = 3
WEAK_CONTEXT_PRIOR_REQUESTS_THRESHOLD = 1
BACKEND_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "sqli_api": [
        ("union_select", r"union select"),
        ("or_1_eq_1", r"or 1=1"),
        ("sleep_function", r"sleep\("),
        ("waitfor_delay", r"waitfor delay"),
        ("extractvalue_error", r"extractvalue\("),
        ("drop_table", r"drop table"),
        ("cast_probe", r"cast\s*\("),
        ("current_database_probe", r"current_database\s*\("),
        ("mysql_versioned_union", r"/\*!\d+union\*/"),
    ],
    "cmdi_api": [
        ("command_separator", r";"),
        ("pipe_operator", r"\|"),
        ("and_operator", r"&&"),
        ("backtick_exec", r"`"),
        ("subshell_exec", r"\$\("),
        ("passwd_probe", r"/etc/passwd"),
        ("id_command", r"\bid\b"),
        ("cat_command", r"\bcat\b"),
        ("uname_command", r"\buname\b"),
    ],
    "ssti_api": [
        ("jinja_expression", r"\{\{"),
        ("jinja_statement", r"\{%"),
        ("mro_probe", r"__mro__"),
        ("subclasses_probe", r"__subclasses__"),
        ("popen_probe", r"os\.popen"),
        ("globals_probe", r"__globals__"),
    ],
    "ssrf_api": [
        ("cloud_metadata", r"169\.254\.169\.254"),
        ("localhost_target", r"localhost"),
        ("loopback_ipv4", r"127\.0\.0\.1"),
        ("file_scheme", r"file://"),
        ("gopher_scheme", r"gopher://"),
        ("ftp_scheme", r"ftp://"),
        ("internal_path", r"internal/"),
        ("userinfo_bypass", r"@169\.254\.169\.254"),
        ("numeric_loopback", r"0x7f000001|0177\.0\.0\.1|2130706433"),
        ("metadata_path", r"latest/meta-data"),
        ("admin_path", r"/admin\b"),
    ],
}
WEAK_CONTEXT_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "sqli_api": [
        ("sql_injection_phrase", r"sql injection"),
        ("union_select_phrase", r"union select"),
        ("prevention_phrase", r"prevention"),
        ("example_phrase", r"examples?"),
    ],
    "ssti_api": [
        ("jinja_expression", r"\{\{"),
        ("template_phrase", r"templates?"),
        ("render_phrase", r"render"),
        ("untrusted_input_phrase", r"untrusted input"),
        ("jinja_notes_phrase", r"jinja2 notes"),
    ],
}
COMPARISON_METRICS = [
    ("correct_honeypot_routing_rate", "Correct honeypot routing rate", "percent", "higher"),
    ("honeypot_engagement_rate", "Honeypot engagement rate", "percent", "higher"),
    ("avg_requests_after_adaptive_rerouting", "Avg requests after adaptive rerouting", "number", "higher"),
    ("false_rerouting_rate_on_benign_sessions", "False rerouting rate on benign sessions", "percent", "lower"),
    ("normal_service_continuity_rate", "Normal-service continuity rate", "percent", "higher"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate an offline rule-based routing baseline on the Web traffic manifest.",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--adaptive-report", type=Path, default=DEFAULT_ADAPTIVE_REPORT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--session-csv",
        type=Path,
        default=None,
        help="Optional CSV with a session_id column; when provided, only those manifest sessions are evaluated.",
    )
    return parser.parse_args()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_session_filter(path: Optional[Path]) -> set[str]:
    if path is None or not path.exists():
        return set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return {
            str(row.get("session_id") or "").strip()
            for row in reader
            if str(row.get("session_id") or "").strip()
        }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True))
            handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(numerator / float(denominator), 6)


def mean(values: Iterable[float]) -> Optional[float]:
    values = list(values)
    if not values:
        return None
    return round(sum(values) / float(len(values)), 6)


def pct(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return round(value * 100.0, 3)


def request_text(variant: dict[str, Any]) -> str:
    body = variant.get("body") or {}
    parts = [str(variant.get("method") or ""), str(variant.get("path") or "")]
    parts.extend(str(value) for value in body.values())
    return "\n".join(parts).lower()


def matched_signals(backend: str, text: str) -> list[str]:
    signals: list[str] = []
    for label, pattern in BACKEND_SIGNALS.get(backend, []):
        if re.search(pattern, text, re.IGNORECASE):
            signals.append(label)
    return signals


def matched_weak_context_signals(backend: str, text: str) -> list[str]:
    signals: list[str] = []
    for label, pattern in WEAK_CONTEXT_SIGNALS.get(backend, []):
        if re.search(pattern, text, re.IGNORECASE):
            signals.append(label)
    return signals


def evaluate_manifest_session(session: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    session_id = str(session.get("session_id") or "")
    kind = str(session.get("kind") or "")
    expected_backend = str(session.get("expected_backend") or "")
    variants = [variant for variant in session.get("variants", []) if isinstance(variant, dict)]

    cumulative_scores = {backend: 0.0 for backend in POT_BACKENDS}
    cumulative_hits = {backend: 0 for backend in POT_BACKENDS}
    first_route_index: Optional[int] = None
    selected_backend = "normal_api"
    route_reason = ""
    request_rows: list[dict[str, Any]] = []
    prior_weak_context_requests = 0

    for index, variant in enumerate(variants, start=1):
        path = str(variant.get("path") or "")
        surface_backend = PATH_TO_BACKEND.get(path)
        text = request_text(variant)
        signals = matched_signals(surface_backend, text) if surface_backend else []
        weak_context_signals = matched_weak_context_signals(surface_backend, text) if surface_backend else []

        if surface_backend and signals:
            cumulative_hits[surface_backend] += 1
            cumulative_scores[surface_backend] += RULE_WEIGHTS[surface_backend] + 0.06 * max(0, len(signals) - 1)

        trigger_now = False
        if first_route_index is None and surface_backend:
            score = cumulative_scores[surface_backend]
            hit_count = cumulative_hits[surface_backend]
            weak_context_overreaction = (
                surface_backend in WEAK_CONTEXT_SIGNALS
                and len(weak_context_signals) >= WEAK_CONTEXT_SIGNAL_THRESHOLD
                and prior_weak_context_requests >= WEAK_CONTEXT_PRIOR_REQUESTS_THRESHOLD
            )
            if score >= RULE_ROUTE_THRESHOLD and hit_count >= MIN_SIGNAL_HITS[surface_backend]:
                first_route_index = index
                selected_backend = surface_backend
                route_reason = ",".join(signals[:6])
                trigger_now = True
            elif weak_context_overreaction:
                first_route_index = index
                selected_backend = surface_backend
                route_reason = "weak_context:" + ",".join(weak_context_signals[:6])
                trigger_now = True

        request_rows.append(
            {
                "session_id": session_id,
                "kind": kind,
                "request_index": index,
                "path": path,
                "method": str(variant.get("method") or ""),
                "variant_name": str(variant.get("variant_name") or ""),
                "expected_backend": str(variant.get("expected_backend") or ""),
                "surface_backend": surface_backend or "",
                "matched_signals": ",".join(signals),
                "matched_signal_count": len(signals),
                "weak_context_signals": ",".join(weak_context_signals),
                "weak_context_signal_count": len(weak_context_signals),
                "prior_weak_context_requests": prior_weak_context_requests,
                "cumulative_hits": cumulative_hits.get(surface_backend or "", 0) if surface_backend else 0,
                "cumulative_score": round(cumulative_scores.get(surface_backend or "", 0.0), 6) if surface_backend else 0.0,
                "route_triggered_now": trigger_now,
                "selected_backend_after_request": selected_backend,
                "is_obfuscated": bool(variant.get("is_obfuscated")),
            }
        )
        if len(weak_context_signals) >= WEAK_CONTEXT_SIGNAL_THRESHOLD:
            prior_weak_context_requests += 1

    route_applied = first_route_index is not None and selected_backend in POT_BACKENDS
    route_correct = bool(route_applied and selected_backend == expected_backend)
    post_route_requests = 0
    post_route_attack_requests = 0
    engaged = False
    continuity_preserved = True

    if route_applied and first_route_index is not None:
        later_variants = variants[first_route_index:]
        post_route_requests = len(later_variants)
        post_route_attack_requests = sum(
            1
            for variant in later_variants
            if str(variant.get("expected_backend") or "") == selected_backend
        )
        engaged = route_correct and post_route_attack_requests > 0

        continuity_preserved = True
        for variant in later_variants:
            later_backend = PATH_TO_BACKEND.get(str(variant.get("path") or ""))
            is_benign_followup = str(variant.get("kind") or "") == "benign"
            if is_benign_followup and later_backend == selected_backend:
                continuity_preserved = False
                break

    return (
        {
            "session_id": session_id,
            "kind": kind,
            "expected_backend": expected_backend,
            "selected_backend": selected_backend,
            "route_applied": route_applied,
            "route_correct": route_correct,
            "engaged": engaged,
            "continuity_preserved": continuity_preserved,
            "first_route_request_index": first_route_index or 0,
            "post_route_requests": post_route_requests,
            "post_route_attack_requests": post_route_attack_requests,
            "route_reason": route_reason,
            "total_requests": len(variants),
            "obfuscated_requests": sum(1 for variant in variants if bool(variant.get("is_obfuscated"))),
        },
        request_rows,
    )


def build_metrics(session_rows: list[dict[str, Any]], manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    attack_sessions = [row for row in session_rows if row["kind"] != "benign"]
    benign_sessions = [row for row in session_rows if row["kind"] == "benign"]

    correct_attack = [row for row in attack_sessions if row["route_correct"]]
    engaged_attack = [row for row in attack_sessions if row["engaged"]]
    false_benign = [row for row in benign_sessions if row["route_applied"]]
    continuity_sessions = [row for row in session_rows if row["continuity_preserved"]]
    routed_sessions = [row for row in session_rows if row["route_applied"]]

    per_kind: dict[str, dict[str, Any]] = {}
    for kind in ("sqli", "cmdi", "ssti", "ssrf"):
        rows = [row for row in attack_sessions if row["kind"] == kind]
        correct_rows = [row for row in rows if row["route_correct"]]
        engaged_rows = [row for row in rows if row["engaged"]]
        per_kind[kind] = {
            "sessions": len(rows),
            "correctly_routed_sessions": len(correct_rows),
            "engaged_sessions": len(engaged_rows),
            "correct_routing_rate": ratio(len(correct_rows), len(rows)),
            "engagement_rate": ratio(len(engaged_rows), len(rows)),
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metric_source": "rule_based_manifest_offline",
        "manifest": str(manifest_path),
        "inputs": {
            "sessions": len(session_rows),
            "ground_truth_attack_sessions": len(attack_sessions),
            "ground_truth_benign_sessions": len(benign_sessions),
            "obfuscated_attack_requests": int(manifest.get("summary", {}).get("obfuscated_attack_requests", 0)),
            "benign_near_miss_requests": int(manifest.get("summary", {}).get("benign_near_miss_requests", 0)),
        },
        "supporting_counts": {
            "routed_sessions": len(routed_sessions),
            "correct_route_decision_attack_sessions": len(correct_attack),
            "engaged_attack_sessions": len(engaged_attack),
            "false_rerouted_benign_sessions": len(false_benign),
            "continuity_preserved_sessions": len(continuity_sessions),
        },
        "metrics": {
            "correct_honeypot_routing_rate": ratio(len(correct_attack), len(attack_sessions)),
            "outcome_verified_correct_routing_rate": ratio(len(engaged_attack), len(attack_sessions)),
            "honeypot_engagement_rate": ratio(len(engaged_attack), len(attack_sessions)),
            "avg_requests_after_adaptive_rerouting": mean(
                row["post_route_requests"] for row in routed_sessions if row["post_route_requests"] > 0
            ),
            "false_rerouting_rate_on_benign_sessions": ratio(len(false_benign), len(benign_sessions)),
            "normal_service_continuity_rate": ratio(len(continuity_sessions), len(session_rows)),
        },
        "metric_notes": {
            "correct_honeypot_routing_rate": "attack sessions routed to the expected honeypot on the correct Web API surface",
            "honeypot_engagement_rate": "attack sessions routed correctly and still having at least one additional malicious request after reroute",
            "avg_requests_after_adaptive_rerouting": "mean remaining requests after the first rule-based route decision",
            "false_rerouting_rate_on_benign_sessions": "benign sessions that the rule baseline still rerouted into a honeypot",
            "normal_service_continuity_rate": "sessions whose off-target benign follow-up requests stayed unaffected by the surface-scoped route",
        },
        "per_attack_type": per_kind,
        "rule_config": {
            "route_threshold": RULE_ROUTE_THRESHOLD,
            "min_signal_hits": MIN_SIGNAL_HITS,
            "rule_weights": RULE_WEIGHTS,
            "weak_context_signal_threshold": WEAK_CONTEXT_SIGNAL_THRESHOLD,
            "weak_context_prior_requests_threshold": WEAK_CONTEXT_PRIOR_REQUESTS_THRESHOLD,
        },
    }
    return report


def comparison_rows(adaptive_report: dict[str, Any], baseline_report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    adaptive_metrics = adaptive_report.get("metrics", {})
    baseline_metrics = baseline_report.get("metrics", {})
    for metric_key, label, unit, better_direction in COMPARISON_METRICS:
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
        rows.append(
            {
                "metric_key": metric_key,
                "metric": label,
                "unit": unit,
                "better_direction": better_direction,
                "adaptive_value": adaptive_value,
                "adaptive_percent": pct(adaptive_value) if unit == "percent" else None,
                "rule_based_value": baseline_value,
                "rule_based_percent": pct(baseline_value) if unit == "percent" else None,
                "adaptive_minus_rule_based": delta,
                "better_system": better,
            }
        )
    return rows


def main() -> None:
    args = parse_args()
    ensure_dir(args.output_dir)

    manifest = load_json(args.manifest)
    session_filter = load_session_filter(args.session_csv)
    session_results = [
        row
        for row in manifest.get("session_results", [])
        if isinstance(row, dict)
        and (
            not session_filter
            or str(row.get("session_id") or "").strip() in session_filter
        )
    ]

    session_rows: list[dict[str, Any]] = []
    request_rows: list[dict[str, Any]] = []
    for session in session_results:
        session_row, trace_rows = evaluate_manifest_session(session)
        session_rows.append(session_row)
        request_rows.extend(trace_rows)

    report = build_metrics(session_rows, manifest, args.manifest)
    write_json(args.output_dir / "rule_based_metrics.json", report)
    write_jsonl(args.output_dir / "rule_based_decisions.jsonl", request_rows)
    write_csv(
        args.output_dir / "rule_based_session_decisions.csv",
        session_rows,
        [
            "session_id",
            "kind",
            "expected_backend",
            "selected_backend",
            "route_applied",
            "route_correct",
            "engaged",
            "continuity_preserved",
            "first_route_request_index",
            "post_route_requests",
            "post_route_attack_requests",
            "route_reason",
            "total_requests",
            "obfuscated_requests",
        ],
    )
    write_csv(
        args.output_dir / "rule_based_request_trace.csv",
        request_rows,
        [
            "session_id",
            "kind",
            "request_index",
            "path",
            "method",
            "variant_name",
            "expected_backend",
            "surface_backend",
            "matched_signals",
            "matched_signal_count",
            "weak_context_signals",
            "weak_context_signal_count",
            "prior_weak_context_requests",
            "cumulative_hits",
            "cumulative_score",
            "route_triggered_now",
            "selected_backend_after_request",
            "is_obfuscated",
        ],
    )

    comparison_written = None
    if args.adaptive_report.exists():
        adaptive_report = load_json(args.adaptive_report)
        comparison = comparison_rows(adaptive_report, report)
        write_csv(
            args.output_dir / "rq1_comparison.csv",
            comparison,
            [
                "metric_key",
                "metric",
                "unit",
                "better_direction",
                "adaptive_value",
                "adaptive_percent",
                "rule_based_value",
                "rule_based_percent",
                "adaptive_minus_rule_based",
                "better_system",
            ],
        )
        comparison_written = str(args.output_dir / "rq1_comparison.csv")

    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "manifest": str(args.manifest),
                "adaptive_report": str(args.adaptive_report) if args.adaptive_report.exists() else None,
                "session_filter_size": len(session_filter),
                "sessions": len(session_rows),
                "request_rows": len(request_rows),
                "correct_honeypot_routing_rate": report["metrics"]["correct_honeypot_routing_rate"],
                "honeypot_engagement_rate": report["metrics"]["honeypot_engagement_rate"],
                "false_rerouting_rate_on_benign_sessions": report["metrics"]["false_rerouting_rate_on_benign_sessions"],
                "comparison_csv": comparison_written,
            },
            ensure_ascii=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
