#!/usr/bin/env python3
import requests
import json

BASE_URL = 'http://localhost:5000'

# Test all 4 honeypots with attack payloads
tests = [
    ('sqli', '/api/articles/search', "' OR '1'='1"),
    ('ssti', '/api/tools/preview', '{{7*7}}'),
    ('ssrf', '/api/tools/fetch', 'http://127.0.0.1:8000'),
    ('cmdi', '/api/tools/ping', '127.0.0.1;whoami'),
]

print("Testing honeypots with attack payloads:\n")
for pot_id, endpoint, payload in tests:
    try:
        url = f"{BASE_URL}/api/honeypot/test/{pot_id}?endpoint={endpoint}&payload={payload}"
        r = requests.post(url, timeout=5)
        j = r.json()
        status = "✅ DETECTED" if j.get('detected') else "❌ NOT DETECTED"
        print(f"[{pot_id.upper():4}] {status} | Status: {j.get('status_code'):3} | Response: {str(j.get('response', {}))[:60]}...")
    except Exception as e:
        print(f"[{pot_id.upper():4}] ❌ ERROR: {str(e)}")

print("\n\nTesting honeypots with normal payloads (should NOT detect):\n")
normal_tests = [
    ('sqli', '/api/articles/search', 'python'),
    ('ssti', '/api/tools/preview', 'hello world'),
    ('ssrf', '/api/tools/fetch', 'https://example.com'),
    ('cmdi', '/api/tools/ping', '127.0.0.1'),
]

for pot_id, endpoint, payload in normal_tests:
    try:
        url = f"{BASE_URL}/api/honeypot/test/{pot_id}?endpoint={endpoint}&payload={payload}"
        r = requests.post(url, timeout=5)
        j = r.json()
        status = "✅ CLEAN" if not j.get('detected') else "❌ FALSE POSITIVE"
        print(f"[{pot_id.upper():4}] {status} | Status: {j.get('status_code'):3}")
    except Exception as e:
        print(f"[{pot_id.upper():4}] ❌ ERROR: {str(e)}")
