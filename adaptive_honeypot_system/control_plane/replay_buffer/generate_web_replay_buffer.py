from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

CONTROL_PLANE_DIR = Path(__file__).resolve().parents[1]
REPLAY_BUFFER_DIR = CONTROL_PLANE_DIR / "replay_buffer"
RL_AGENT_DIR = CONTROL_PLANE_DIR / "rl_agent"
SYSTEM_DIR = CONTROL_PLANE_DIR.parent

for path in (CONTROL_PLANE_DIR, REPLAY_BUFFER_DIR, RL_AGENT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from export_replay_buffer import (  # noqa: E402
    build_transitions,
    collect_decisions,
    group_outcome_events,
    load_jsonl,
    write_jsonl,
)


ATTACK_WEIGHTS = {
    "benign": 0.20,
    "sqli": 0.22,
    "cmdi": 0.20,
    "ssti": 0.20,
    "ssrf": 0.18,
}


@dataclass(frozen=True)
class TrafficCase:
    kind: str
    method: str
    path: str
    body: dict[str, Any]
    expected_backend: Optional[str]


CASES = {
    "sqli": TrafficCase(
        kind="sqli",
        method="POST",
        path="/api/articles/search",
        body={"query": "union select password from users"},
        expected_backend="sqli_api",
    ),
    "cmdi": TrafficCase(
        kind="cmdi",
        method="POST",
        path="/api/tools/ping",
        body={"host": "8.8.8.8; id"},
        expected_backend="cmdi_api",
    ),
    "ssti": TrafficCase(
        kind="ssti",
        method="POST",
        path="/api/tools/preview",
        body={
            "content": (
                "# Replay Buffer\n\n"
                "Type some **Markdown** here.\n\n"
                "```python\nprint(\"hello\")\n```\n\n"
                "{{7*7}}"
            )
        },
        expected_backend="ssti_api",
    ),
    "ssrf": TrafficCase(
        kind="ssrf",
        method="POST",
        path="/api/tools/fetch",
        body={"url": "http://169.254.169.254/latest/meta-data/"},
        expected_backend="ssrf_api",
    ),
}


ATTACK_VARIANTS = {
    "sqli": [
        {"query": "uNiOn/**/SeLeCt/**/password/**/FrOm/**/users--"},
        {"query": "' OR/**/1=1--"},
        {"query": "admin' AND extractvalue(1,concat(0x7e,(select database())))--"},
        {"query": "%27%20UNION%20SELECT%20NULL,password%20FROM%20users--"},
        {"query": "1';WAITFOR DELAY '0:0:2'--"},
        {"query": "Robert'); DROP TABLE audit_log;--"},
    ],
    "cmdi": [
        {"host": "8.8.8.8&&id"},
        {"host": "127.0.0.1|whoami"},
        {"host": "localhost$(id)"},
        {"host": "8.8.8.8%3Bid"},
        {"host": "example.com`uname -a`"},
        {"host": "1.1.1.1\nid"},
    ],
    "ssti": [
        {"content": "# Notes\n\n{{7*7}}\n\nNormal **markdown** around the expression."},
        {"content": "# Invoice\n\nSubtotal: {{ 6 * 7 }}\n\n```jinja2\n{{config}}\n```"},
        {"content": "{% for x in [7] %}{{x*x}}{% endfor %}\n\nKeep rendering markdown."},
        {"content": "# Debug\n\n{{ ''.__class__.__mro__[1].__subclasses__()[:2] }}"},
        {"content": "# Mixed\n\nType some **Markdown** here.\n\n${{7*7}}\n\n{{7*7}}"},
    ],
    "ssrf": [
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        {"url": "http://[::ffff:169.254.169.254]/latest/meta-data/"},
        {"url": "http://0177.0.0.1/admin"},
        {"url": "http://localhost:5000/internal/status"},
        {"url": "http://2130706433/latest/meta-data/"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/"},
    ],
}


BENIGN_REQUESTS = [
    TrafficCase("benign", "GET", "/api/articles?page=1&limit=2", {}, None),
    TrafficCase("benign", "POST", "/api/articles/search", {"query": "tcp"}, None),
    TrafficCase("benign", "POST", "/api/tools/preview", {"content": "# Hello\n\nNormal markdown."}, None),
]


BENIGN_NEAR_MISS_REQUESTS = [
    TrafficCase(
        "benign",
        "POST",
        "/api/articles/search",
        {"query": "SQL injection prevention union select examples"},
        None,
    ),
    TrafficCase(
        "benign",
        "POST",
        "/api/tools/preview",
        {"content": "# Jinja2 notes\n\nUse `{{ user.name }}` in templates, but never render untrusted input."},
        None,
    ),
    TrafficCase("benign", "POST", "/api/tools/ping", {"host": "8.8.8.8"}, None),
    TrafficCase("benign", "POST", "/api/tools/fetch", {"url": "https://example.com"}, None),
]


CROSS_SURFACE_REQUESTS = {
    "sqli": TrafficCase("benign", "POST", "/api/tools/preview", {"content": "# Cross surface"}, None),
    "cmdi": TrafficCase("benign", "POST", "/api/tools/preview", {"content": "# Cross surface"}, None),
    "ssti": TrafficCase("benign", "POST", "/api/tools/ping", {"host": "bad host"}, None),
    "ssrf": TrafficCase("benign", "POST", "/api/tools/preview", {"content": "# Cross surface"}, None),
}


def variant_case(kind: str, rng: random.Random, evasion_ratio: float) -> TrafficCase:
    base_case = CASES[kind]
    variants = ATTACK_VARIANTS.get(kind) or []
    if not variants or rng.random() > evasion_ratio:
        return base_case
    return TrafficCase(
        kind=base_case.kind,
        method=base_case.method,
        path=base_case.path,
        body=dict(rng.choice(variants)),
        expected_backend=base_case.expected_backend,
    )


def now_run_id() -> str:
    return time.strftime("%Y%m%d%H%M%S", time.gmtime())


def request_json(
    *,
    base_url: str,
    case: TrafficCase,
    session_id: str,
    timeout: float,
) -> tuple[int, str]:
    url = f"{base_url.rstrip('/')}{case.path}"
    headers = {
        "User-Agent": "adaptive-replay-buffer-generator/1.0",
        "Cookie": f"sid={session_id}",
    }
    data: Optional[bytes] = None
    if case.method.upper() != "GET":
        data = json.dumps(case.body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=case.method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", errors="replace")


def controller_json(controller_url: str, path: str, *, method: str = "GET", timeout: float = 5.0) -> dict[str, Any]:
    request = urllib.request.Request(f"{controller_url.rstrip('/')}{path}", method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def clear_routes(controller_url: str) -> None:
    controller_json(controller_url, "/routes", method="DELETE")


def route_for_session(controller_url: str, session_id: str) -> Optional[str]:
    try:
        body = controller_json(controller_url, f"/route/session/{session_id}")
    except Exception:
        return None
    if not body.get("found"):
        return None
    backend = body.get("backend")
    return str(backend) if backend else None


def wait_for_route(
    *,
    controller_url: str,
    session_id: str,
    expected_backend: str,
    timeout: float,
    interval: float,
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if route_for_session(controller_url, session_id) == expected_backend:
            return True
        time.sleep(interval)
    return False


def validate_preflight_response(kind: str, status: int, body: str) -> bool:
    if kind == "sqli":
        return status == 500 and "SQL syntax" in body
    if kind == "cmdi":
        return status == 200 and "uid=33" in body
    if kind == "ssti":
        return status == 200 and "49" in body and "Markdown" in body
    if kind == "ssrf":
        return status == 200 and "instanceId" in body
    return False


def preflight_adaptive_routes(
    *,
    base_url: str,
    controller_url: str,
    request_timeout: float,
) -> None:
    clear_routes(controller_url)
    for kind, case in CASES.items():
        session_id = f"preflight_{int(time.time())}_{kind}"
        if not case.expected_backend:
            continue
        controller_json(
            controller_url,
            f"/route/session/{session_id}?backend={case.expected_backend}",
            method="POST",
        )
        status, body = request_json(
            base_url=base_url,
            case=case,
            session_id=session_id,
            timeout=request_timeout,
        )
        if not validate_preflight_response(kind, status, body):
            snippet = body.replace("\n", " ")[:160]
            raise RuntimeError(
                f"Preflight failed for {kind}: status={status}, expected_backend={case.expected_backend}, "
                f"body={snippet!r}. Recreate gateway if HAProxy resolved stale container IPs."
            )
    clear_routes(controller_url)


def allocate_kinds(total: int, weights: dict[str, float], rng: random.Random) -> list[str]:
    if total <= 0:
        return []

    raw_counts = {kind: total * weight for kind, weight in weights.items()}
    counts = {kind: int(value) for kind, value in raw_counts.items()}
    remaining = total - sum(counts.values())
    fractional = sorted(
        ((kind, raw_counts[kind] - counts[kind]) for kind in weights),
        key=lambda item: item[1],
        reverse=True,
    )
    for kind, _ in fractional[:remaining]:
        counts[kind] += 1

    kinds: list[str] = []
    for kind, count in counts.items():
        kinds.extend([kind] * count)
    rng.shuffle(kinds)
    return kinds


def iter_log_files(logs_dir: Path) -> Iterable[Path]:
    if not logs_dir.exists():
        return []
    return sorted(path for path in logs_dir.rglob("*.jsonl") if path.is_file())


def collect_events_for_prefix(*, logs_dir: Path, prefix: str, output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output_path.open("w", encoding="utf-8") as output:
        for path in iter_log_files(logs_dir):
            with path.open("r", encoding="utf-8") as source:
                for line_no, line in enumerate(source, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc
                    session_id = str(record.get("session_id") or "")
                    if not session_id.startswith(prefix):
                        continue
                    output.write(json.dumps(record, ensure_ascii=True) + "\n")
                    written += 1
    return written


def export_transitions(
    *,
    events_path: Path,
    output_path: Path,
    horizon_seconds: float,
    session_timeout_seconds: float,
    attack_threshold: float,
) -> dict[str, Any]:
    events = load_jsonl(events_path)
    decisions = collect_decisions(events)
    outcomes_by_session = group_outcome_events(events)
    transitions = build_transitions(
        decisions=decisions,
        outcomes_by_session=outcomes_by_session,
        horizon_seconds=horizon_seconds,
        session_timeout_seconds=session_timeout_seconds,
        attack_threshold=attack_threshold,
    )
    written = write_jsonl(output_path, transitions)
    return {
        "events": len(events),
        "decisions": len(decisions),
        "sessions": len({row["session_id"] for row in transitions}),
        "transitions": written,
        "action_counts": dict(Counter(row["action_name"] for row in transitions)),
        "reward_min": min((float(row["reward"]) for row in transitions), default=0.0),
        "reward_max": max((float(row["reward"]) for row in transitions), default=0.0),
    }


def drive_session(
    *,
    base_url: str,
    controller_url: str,
    session_id: str,
    kind: str,
    route_timeout: float,
    route_poll_interval: float,
    request_timeout: float,
    followups: int,
    evasion_ratio: float,
    benign_near_miss_ratio: float,
    rng: random.Random,
) -> dict[str, Any]:
    statuses: list[int] = []
    variants_used: list[dict[str, Any]] = []
    routed = False
    expected_backend: Optional[str] = None

    if kind == "benign":
        requests = list(BENIGN_REQUESTS)
        near_miss_count = 0
        for near_miss in BENIGN_NEAR_MISS_REQUESTS:
            if rng.random() <= benign_near_miss_ratio:
                requests.append(near_miss)
                near_miss_count += 1
        rng.shuffle(requests)
        for case in requests:
            status, _ = request_json(base_url=base_url, case=case, session_id=session_id, timeout=request_timeout)
            statuses.append(status)
            time.sleep(rng.uniform(0.05, 0.18))
        return {
            "session_id": session_id,
            "kind": kind,
            "expected_backend": None,
            "routed": False,
            "statuses": statuses,
            "variants": {"benign_near_miss_requests": near_miss_count},
        }

    case = variant_case(kind, rng, evasion_ratio)
    expected_backend = case.expected_backend
    status, _ = request_json(base_url=base_url, case=case, session_id=session_id, timeout=request_timeout)
    statuses.append(status)
    variants_used.append(case.body)

    if expected_backend:
        routed = wait_for_route(
            controller_url=controller_url,
            session_id=session_id,
            expected_backend=expected_backend,
            timeout=route_timeout,
            interval=route_poll_interval,
        )

    for _ in range(max(1, followups)):
        case = variant_case(kind, rng, evasion_ratio)
        status, _ = request_json(base_url=base_url, case=case, session_id=session_id, timeout=request_timeout)
        statuses.append(status)
        variants_used.append(case.body)
        time.sleep(rng.uniform(0.04, 0.14))

    cross_surface = CROSS_SURFACE_REQUESTS.get(kind)
    if cross_surface:
        status, _ = request_json(
            base_url=base_url,
            case=cross_surface,
            session_id=session_id,
            timeout=request_timeout,
        )
        statuses.append(status)

    return {
        "session_id": session_id,
        "kind": kind,
        "expected_backend": expected_backend,
        "routed": routed,
        "statuses": statuses,
        "variants": variants_used,
    }


def parse_args() -> argparse.Namespace:
    run_id = now_run_id()
    default_prefix = f"replay_{run_id}"
    default_events = CONTROL_PLANE_DIR / "replay_buffer" / "data" / f"{default_prefix}_events.jsonl"
    default_output = CONTROL_PLANE_DIR / "rl_agent" / "data" / "replay_buffer.jsonl"

    parser = argparse.ArgumentParser(
        description="Generate Web traffic through the gateway and export host logs into an offline RL replay buffer.",
    )
    parser.add_argument("--gateway-url", default="http://localhost:18080")
    parser.add_argument("--controller-url", default="http://localhost:8001")
    parser.add_argument("--logs-dir", type=Path, default=SYSTEM_DIR / "logs")
    parser.add_argument("--sessions", type=int, default=48)
    parser.add_argument("--prefix", default=default_prefix)
    parser.add_argument("--event-output", type=Path, default=default_events)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--seed", type=int, default=20260524)
    parser.add_argument("--route-timeout", type=float, default=35.0)
    parser.add_argument("--route-poll-interval", type=float, default=1.0)
    parser.add_argument("--request-timeout", type=float, default=8.0)
    parser.add_argument("--followups", type=int, default=2)
    parser.add_argument("--evasion-ratio", type=float, default=0.70)
    parser.add_argument("--benign-near-miss-ratio", type=float, default=0.50)
    parser.add_argument("--post-traffic-wait", type=float, default=7.0)
    parser.add_argument("--horizon-seconds", type=float, default=60.0)
    parser.add_argument("--session-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--attack-threshold", type=float, default=0.45)
    parser.add_argument("--no-clear-routes", action="store_true")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--keep-routes", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.sessions <= 0:
        raise ValueError("--sessions must be > 0")
    if args.followups < 0:
        raise ValueError("--followups must be >= 0")
    if not 0.0 <= args.evasion_ratio <= 1.0:
        raise ValueError("--evasion-ratio must be between 0 and 1")
    if not 0.0 <= args.benign_near_miss_ratio <= 1.0:
        raise ValueError("--benign-near-miss-ratio must be between 0 and 1")
    if args.no_clear_routes and not args.skip_preflight:
        raise ValueError("--no-clear-routes requires --skip-preflight")

    rng = random.Random(args.seed)
    kinds = allocate_kinds(args.sessions, ATTACK_WEIGHTS, rng)

    if not args.no_clear_routes:
        clear_routes(args.controller_url)
        if not args.skip_preflight:
            preflight_adaptive_routes(
                base_url=args.gateway_url,
                controller_url=args.controller_url,
                request_timeout=args.request_timeout,
            )

    session_results: list[dict[str, Any]] = []
    for idx, kind in enumerate(kinds, start=1):
        session_id = f"{args.prefix}_{idx:04d}_{kind}"
        result = drive_session(
            base_url=args.gateway_url,
            controller_url=args.controller_url,
            session_id=session_id,
            kind=kind,
            route_timeout=args.route_timeout,
            route_poll_interval=args.route_poll_interval,
            request_timeout=args.request_timeout,
            followups=args.followups,
            evasion_ratio=args.evasion_ratio,
            benign_near_miss_ratio=args.benign_near_miss_ratio,
            rng=rng,
        )
        session_results.append(result)
        print(
            f"[{idx:03d}/{args.sessions:03d}] {kind:<6} "
            f"sid={session_id} routed={result['routed']} statuses={result['statuses']}",
            flush=True,
        )

    if args.post_traffic_wait > 0:
        time.sleep(args.post_traffic_wait)

    event_count = collect_events_for_prefix(
        logs_dir=args.logs_dir,
        prefix=args.prefix,
        output_path=args.event_output,
    )
    export_stats = export_transitions(
        events_path=args.event_output,
        output_path=args.output,
        horizon_seconds=args.horizon_seconds,
        session_timeout_seconds=args.session_timeout_seconds,
        attack_threshold=args.attack_threshold,
    )

    kind_counts = Counter(result["kind"] for result in session_results)
    routed_counts = Counter(result["kind"] for result in session_results if result["routed"])
    near_miss_requests = sum(
        int((result.get("variants") or {}).get("benign_near_miss_requests", 0))
        for result in session_results
        if result["kind"] == "benign"
    )

    print("Replay traffic generation complete", flush=True)
    print(f"- Prefix: {args.prefix}", flush=True)
    print(f"- Session mix: {dict(kind_counts)}", flush=True)
    print(f"- Routed attack sessions: {dict(routed_counts)}", flush=True)
    print(f"- Evasion ratio: {args.evasion_ratio}", flush=True)
    print(f"- Benign near-miss requests: {near_miss_requests}", flush=True)
    print(f"- Host events collected: {event_count}", flush=True)
    print(f"- Event JSONL: {args.event_output}", flush=True)
    print(f"- Replay buffer: {args.output}", flush=True)
    print(f"- Export stats: {export_stats}", flush=True)

    if not args.keep_routes and not args.no_clear_routes:
        clear_routes(args.controller_url)
        print("- Adaptive routes cleared after export", flush=True)

    if export_stats["transitions"] == 0:
        raise RuntimeError("No replay transitions generated; check analyzer logs and route decisions.")


if __name__ == "__main__":
    main()
