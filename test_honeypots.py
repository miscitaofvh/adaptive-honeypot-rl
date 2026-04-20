#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class TestCase:
    name: str
    method: str
    url: str
    fallback_url: str | None
    payload: dict[str, Any] | None
    validator: Callable[[int, dict[str, Any]], tuple[bool, str]]


def request_json(method: str, url: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
            return resp.getcode(), parsed
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = json.loads(body) if body else {}
        return exc.code, parsed


def validate_health(expected_service: str) -> Callable[[int, dict[str, Any]], tuple[bool, str]]:
    def _validator(status: int, body: dict[str, Any]) -> tuple[bool, str]:
        if status != 200:
            return False, f"expected status 200, got {status}"
        if body.get("service") != expected_service:
            return False, f"expected service {expected_service}, got {body.get('service')}"
        if body.get("status") != "ok":
            return False, f"expected status=ok, got {body.get('status')}"
        return True, "ok"

    return _validator


def validate_cmdi(status: int, body: dict[str, Any]) -> tuple[bool, str]:
    if status != 200:
        return False, f"expected status 200, got {status}"
    output = str(body.get("output", ""))
    if not output:
        return False, "expected non-empty output"
    if "uid=33" not in output and "www-data" not in output:
        return False, f"unexpected output: {output}"
    return True, "ok"


def validate_sqli(status: int, body: dict[str, Any]) -> tuple[bool, str]:
    if status != 500:
        return False, f"expected status 500, got {status}"
    if body.get("error") != "DatabaseError":
        return False, f"expected error DatabaseError, got {body.get('error')}"
    return True, "ok"


def validate_ssti(status: int, body: dict[str, Any]) -> tuple[bool, str]:
    if status != 200:
        return False, f"expected status 200, got {status}"
    rendered = str(body.get("rendered", ""))
    if rendered != "49":
        return False, f"expected rendered=49, got {rendered}"
    return True, "ok"


def validate_ssrf(status: int, body: dict[str, Any]) -> tuple[bool, str]:
    if status != 200:
        return False, f"expected status 200, got {status}"
    content = str(body.get("content", ""))
    if "instanceId" not in content:
        return False, "expected instance metadata content"
    return True, "ok"


def run_tests() -> int:
    tests = [
        TestCase(
            name="CMDI health",
            method="GET",
            url="http://127.0.0.1:5002/api/health",
            fallback_url=None,
            payload=None,
            validator=validate_health("cmdi-honeypot"),
        ),
        TestCase(
            name="SQLI health",
            method="GET",
            url="http://127.0.0.1:5003/api/health",
            fallback_url=None,
            payload=None,
            validator=validate_health("sqli-honeypot"),
        ),
        TestCase(
            name="SSTI health",
            method="GET",
            url="http://127.0.0.1:5004/api/health",
            fallback_url="http://[::1]:5004/api/health",
            payload=None,
            validator=validate_health("ssti-honeypot"),
        ),
        TestCase(
            name="SSRF health",
            method="GET",
            url="http://127.0.0.1:5005/api/health",
            fallback_url=None,
            payload=None,
            validator=validate_health("ssrf-honeypot"),
        ),
        TestCase(
            name="CMDI detection",
            method="POST",
            url="http://127.0.0.1:5002/api/tools/ping",
            fallback_url=None,
            payload={"host": "8.8.8.8;id"},
            validator=validate_cmdi,
        ),
        TestCase(
            name="SQLI detection",
            method="POST",
            url="http://127.0.0.1:5003/api/articles/search",
            fallback_url=None,
            payload={"query": "union select password from users"},
            validator=validate_sqli,
        ),
        TestCase(
            name="SSTI detection",
            method="POST",
            url="http://127.0.0.1:5004/api/tools/preview",
            fallback_url="http://[::1]:5004/api/tools/preview",
            payload={"content": "{{7*7}}"},
            validator=validate_ssti,
        ),
        TestCase(
            name="SSRF detection",
            method="POST",
            url="http://127.0.0.1:5005/api/tools/fetch",
            fallback_url=None,
            payload={"url": "http://169.254.169.254/latest/meta-data/"},
            validator=validate_ssrf,
        ),
    ]

    failed = 0

    print("[Standalone honeypot tests]")
    for test in tests:
        ok = False
        detail = "unknown error"
        candidate_urls = [test.url]
        if test.fallback_url:
            candidate_urls.append(test.fallback_url)

        for attempt in range(1, 4):
            for url in candidate_urls:
                try:
                    status, body = request_json(test.method, url, test.payload)
                    ok, detail = test.validator(status, body)
                    if ok:
                        break
                except Exception as exc:  # noqa: BLE001
                    detail = f"{url}: {exc}"

            if ok:
                break

            if attempt < 3:
                time.sleep(1)

        state = "PASS" if ok else "FAIL"
        print(f"- {state}: {test.name} ({detail})")
        if not ok:
            failed += 1

    if failed:
        print(f"\nFAILED: {failed} test(s) failed")
        return 1

    print("\nALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_tests())
