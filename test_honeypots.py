#!/usr/bin/env python3
import requests


def _post(url, payload):
    resp = requests.post(url, json=payload, timeout=5)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


def test_sqli():
    base = "http://localhost:5003"
    attack_status, attack_data = _post(f"{base}/api/articles/search", {"query": "' OR '1'='1"})
    normal_status, normal_data = _post(f"{base}/api/articles/search", {"query": "python"})

    attack_detected = attack_status >= 500 and "DatabaseError" in str(attack_data)
    normal_clean = normal_status == 200 and isinstance(normal_data.get("items"), list)
    return attack_detected, normal_clean, attack_status, normal_status


def test_ssti():
    base = "http://[::1]:5004"
    attack_status, attack_data = _post(f"{base}/api/tools/preview", {"content": "{{7*7}}"})
    normal_status, normal_data = _post(f"{base}/api/tools/preview", {"content": "hello world"})

    attack_detected = attack_status == 200 and str(attack_data.get("rendered", "")).strip() == "49"
    normal_clean = normal_status == 200 and "hello world" in str(normal_data.get("rendered", ""))
    return attack_detected, normal_clean, attack_status, normal_status


def test_ssrf():
    base = "http://localhost:5005"
    attack_status, attack_data = _post(f"{base}/api/tools/fetch", {"url": "http://169.254.169.254/latest/meta-data"})
    normal_status, normal_data = _post(f"{base}/api/tools/fetch", {"url": "https://example.com"})

    attack_detected = attack_status == 200 and "instanceId" in str(attack_data.get("content", ""))
    normal_clean = normal_status == 200 and str(normal_data.get("content", "")).startswith("<html>")
    return attack_detected, normal_clean, attack_status, normal_status


def test_cmdi():
    base = "http://localhost:5002"
    attack_status, attack_data = _post(f"{base}/api/tools/ping", {"host": "127.0.0.1;whoami"})
    normal_status, normal_data = _post(f"{base}/api/tools/ping", {"host": "127.0.0.1"})

    attack_output = str(attack_data.get("output", ""))
    normal_output = str(normal_data.get("output", ""))

    attack_detected = attack_status == 200 and "www-data" in attack_output
    normal_clean = normal_status == 200 and "www-data" not in normal_output
    return attack_detected, normal_clean, attack_status, normal_status


if __name__ == "__main__":
    tests = [
        ("SQLI", test_sqli),
        ("SSTI", test_ssti),
        ("SSRF", test_ssrf),
        ("CMDI", test_cmdi),
    ]

    print("Testing honeypots with attack and normal payloads:\n")
    failed = 0

    for name, fn in tests:
        try:
            attack_detected, normal_clean, attack_status, normal_status = fn()
            detect_mark = "PASS" if attack_detected else "FAIL"
            clean_mark = "PASS" if normal_clean else "FAIL"
            print(f"[{name}] attack_detected={detect_mark} (status={attack_status}) | normal_clean={clean_mark} (status={normal_status})")
            if not attack_detected or not normal_clean:
                failed += 1
        except Exception as exc:
            failed += 1
            print(f"[{name}] ERROR: {exc}")

    print("\nSummary:")
    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"FAILED TEST CASES: {failed}")
