import ipaddress
import re
import time
from urllib.parse import urlparse

import bleach
import markdown
import ping3
import requests as req_lib
from flask import Blueprint, request, jsonify

tools_bp = Blueprint('tools', __name__)

ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + ['h1','h2','h3','h4','h5','h6','p','pre','code','blockquote','ul','ol','li','hr','br','table','thead','tbody','tr','th','td']
ALLOWED_ATTRS = {**bleach.sanitizer.ALLOWED_ATTRIBUTES, 'code':['class'], 'pre':['class']}


def _bounded_int(value, default, minimum=1, maximum=10):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _text(value):
    if value is None:
        return ''
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _is_private_or_internal_host(hostname):
    host = (hostname or '').strip().strip('[]').rstrip('.').lower()
    if not host:
        return True

    if host == 'localhost' or host.endswith('.localhost'):
        return True

    # Docker service names and short intranet names should not be fetched by the real service.
    if '.' not in host:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return any((
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
    ))


def _validate_public_http_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        return False, 'Only HTTP/HTTPS URLs are supported.'
    if _is_private_or_internal_host(parsed.hostname):
        return False, 'Private or internal URLs are not supported by the real service.'
    return True, ''

@tools_bp.post('/preview')
def preview():
    data = request.get_json(silent=True) or {}
    content = _text(data.get('content'))[:32_000]
    rendered = markdown.markdown(content, extensions=['fenced_code','tables','nl2br'])
    safe = bleach.clean(rendered, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    word_count = len(re.findall(r'\w+', content))
    return jsonify(rendered=safe, word_count=word_count, read_time=max(1,round(word_count/200)))

@tools_bp.post('/ping')
def ping_handler():
    data = request.get_json(silent=True) or {}
    host = _text(data.get('host'))
    count = _bounded_int(data.get('count', 4), 4, 1, 10)
    
    if not host:
        return jsonify(message='host is required'), 400
    if not re.fullmatch(r'[A-Za-z0-9.\-]{1,253}', host):
        return jsonify(message='Invalid host.'), 400
    
    try:
        latencies = []
        reachable = False
        for _ in range(count):
            try:
                delay = ping3.ping(host, timeout=2)
                if delay:
                    latencies.append(delay * 1000)
                    reachable = True
            except Exception:
                pass
        
        avg_latency = sum(latencies) / len(latencies) if latencies else None
        output = f'PING {host}: {count} packets sent, {len(latencies)} received.'
        return jsonify(host=host, reachable=reachable, latency_ms=avg_latency, output=output)
    except Exception as e:
        return jsonify(message=str(e)), 500

@tools_bp.post('/fetch')
def fetch():
    data = request.get_json(silent=True) or {}
    url = _text(data.get('url'))
    
    if not url:
        return jsonify(message='url is required'), 400
    ok, message = _validate_public_http_url(url)
    if not ok:
        return jsonify(message=message), 400
    
    try:
        start = time.monotonic()
        resp = req_lib.get(url, timeout=10, allow_redirects=True, headers={'User-Agent':'Meridian-Real/1.0'})
        ct = resp.headers.get('content-type','')
        body = resp.text[:8_000] if 'text' in ct else '[binary]'
        return jsonify(
            status_code=resp.status_code,
            content_type=ct,
            size_bytes=len(resp.content),
            time_ms=round((time.monotonic()-start)*1000),
            final_url=resp.url,
            content=body
        )
    except req_lib.exceptions.Timeout:
        return jsonify(message='Request timed out.'), 504
    except Exception as e:
        return jsonify(message=str(e)), 500
