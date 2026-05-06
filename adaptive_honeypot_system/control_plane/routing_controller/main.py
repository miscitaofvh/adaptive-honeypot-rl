from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allow importing RL modules from sibling folder.
RL_DIR = Path(__file__).resolve().parents[1] / "rl_agent"
if str(RL_DIR) not in sys.path:
    sys.path.insert(0, str(RL_DIR))

from agent import (  # noqa: E402
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    STATE_DIM,
    LinearQAgent,
    action_backend,
    action_name,
)

logger = logging.getLogger("routing_controller")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = BASE_DIR / "control_plane" / "rl_agent" / "artifacts" / "rl_agent_linear.json"
DEFAULT_ROUTING_SCRIPT = BASE_DIR / "gateway" / "routing_update.sh"

MODEL_PATH = Path(os.getenv("RL_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
ROUTING_SCRIPT = Path(os.getenv("ROUTING_UPDATE_SCRIPT", str(DEFAULT_ROUTING_SCRIPT)))
COMMAND_TIMEOUT_SECONDS = float(os.getenv("ROUTING_COMMAND_TIMEOUT", "5"))
POLICY_MODE = os.getenv("RL_POLICY_MODE", "model").strip().lower()
EXPOSURE_MODE = os.getenv("EXPOSURE_MODE", "debug").strip().lower()
DEBUG_EXPOSURE_VALUES = {"debug", "dev", "development", "operator", "test"}
DEBUG_EXPOSURE = EXPOSURE_MODE in DEBUG_EXPOSURE_VALUES
HEURISTIC_ROUTE_THRESHOLD = float(os.getenv("HEURISTIC_ROUTE_THRESHOLD", "0.45"))
L4_ROUTING_ENABLED = os.getenv("L4_ROUTING_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
SESSION_ROUTES_MAP = Path(os.getenv("SESSION_ROUTES_MAP", "/etc/haproxy/maps/session_routes.map"))
IP_HONEYPOT_MAP = Path(os.getenv("IP_HONEYPOT_MAP", "/etc/haproxy/maps/ip_honeypot.map"))

HTTP_BACKENDS = {
    "normal_api",
    "sqli_api",
    "ssti_api",
    "cmdi_api",
    "ssrf_api",
}

L4_PLACEHOLDER_BACKENDS = {
    "ssh_honeypot",
    "ftp_honeypot",
    "smtp_honeypot",
}

model_lock = threading.Lock()
agent = LinearQAgent(seed=123)


class DecisionRequest(BaseModel):
    protocol: str = Field(default="http")
    state: List[float] = Field(min_length=STATE_DIM, max_length=STATE_DIM)
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    apply_route: bool = True

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"http", "ssh", "ftp", "smtp"}:
            raise ValueError("protocol must be one of: http, ssh, ftp, smtp")
        return value


class DecisionResponse(BaseModel):
    protocol: str
    action_id: int
    action_name: str
    backend: str
    route_applied: bool
    route_command: Optional[str] = None
    route_output: Optional[str] = None


class ReloadModelResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    loaded: bool
    model_path: str
    message: str


class RouteUpdateResponse(BaseModel):
    status: str
    message: str
    command: str
    output: str


class ClearRoutesResponse(BaseModel):
    status: str
    message: str
    command: str
    output: str


def ensure_valid_backend(backend: str, protocol: str = "http") -> str:
    backend = backend.strip()
    if backend in L4_PLACEHOLDER_BACKENDS and not L4_ROUTING_ENABLED:
        raise HTTPException(
            status_code=501,
            detail={
                "message": "L4 routing is intentionally disabled in the current Web MVP",
                "backend": backend,
                "protocol": protocol,
            },
        )

    if protocol != "http" and not L4_ROUTING_ENABLED:
        raise HTTPException(
            status_code=501,
            detail={
                "message": "Non-HTTP Drop-and-Catch routing is not implemented in this milestone",
                "protocol": protocol,
            },
        )

    if backend not in HTTP_BACKENDS:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unsupported backend",
                "backend": backend,
                "allowed_backends": sorted(HTTP_BACKENDS),
            },
        )
    return backend


def require_debug_exposure() -> None:
    if not DEBUG_EXPOSURE:
        raise HTTPException(status_code=404, detail="Not found")


def ensure_valid_ip(source_ip: str) -> str:
    try:
        return str(ip_address(source_ip.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid source_ip: {source_ip}") from exc


def run_command(args: List[str]) -> str:
    completed = subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    output = (completed.stdout or "").strip()
    if not output:
        output = (completed.stderr or "").strip()
    return output


def select_policy_action(req: DecisionRequest) -> int:
    if POLICY_MODE in {"heuristic", "dummy", "rule", "rules"}:
        return heuristic_action(req.state, req.protocol)

    with model_lock:
        action_idx, _ = agent.select_action(req.state, req.protocol)
    return action_idx


def heuristic_action(state: List[float], protocol: str) -> int:
    """Deterministic dummy RL policy for the Web MVP.

    It consumes the same 24D state vector as the trained agent. The policy is
    deliberately conservative: keep benign traffic normal, but route strong
    web subtype evidence to the matching honeypot to maximize attacker
    engagement without protecting/blocking the service path.
    """
    if protocol != "http":
        return ACTION_KEEP_NORMAL

    subtype_candidates = [
        (float(state[13]), ACTION_ROUTE_SQLI),
        (float(state[14]), ACTION_ROUTE_CMDI),
        (float(state[15]), ACTION_ROUTE_SSTI),
        (float(state[16]), ACTION_ROUTE_SSRF),
    ]
    best_score, best_action = max(subtype_candidates, key=lambda item: item[0])
    injection_score = float(state[9])
    evasion_score = float(state[17])

    if best_score >= HEURISTIC_ROUTE_THRESHOLD:
        return best_action
    if injection_score >= 0.65 and evasion_score >= 0.40:
        return best_action
    return ACTION_KEEP_NORMAL


def apply_route_decision(req: DecisionRequest, action_idx: int, backend: str) -> tuple[bool, Optional[str], Optional[str]]:
    if not req.apply_route:
        return False, None, None

    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    command: List[str]

    if req.protocol == "http":
        chosen_backend = ensure_valid_backend(backend, req.protocol)
        # Keep proposal-aligned behavior (session-level on HTTP) and allow IP-level fallback for split-client tests.
        if req.session_id:
            if action_idx == ACTION_KEEP_NORMAL:
                command = [str(ROUTING_SCRIPT), "remove_session", req.session_id]
            else:
                command = [str(ROUTING_SCRIPT), "add_session", req.session_id, chosen_backend]
        elif req.source_ip:
            source_ip = ensure_valid_ip(req.source_ip)
            if action_idx == ACTION_KEEP_NORMAL:
                command = [str(ROUTING_SCRIPT), "remove_ip", source_ip]
            else:
                command = [str(ROUTING_SCRIPT), "add_ip", source_ip, chosen_backend]
        else:
            raise HTTPException(status_code=400, detail="session_id or source_ip is required for HTTP routing updates")
    else:
        if not L4_ROUTING_ENABLED:
            if action_idx == ACTION_KEEP_NORMAL:
                return False, None, "L4 routing disabled; KEEP_NORMAL does not require a route update"
            raise HTTPException(
                status_code=501,
                detail={
                    "message": "L4 Drop-and-Catch routing is not implemented in this milestone",
                    "protocol": req.protocol,
                    "backend": backend,
                },
            )

        if not req.source_ip:
            raise HTTPException(status_code=400, detail="source_ip is required for non-HTTP routing updates")

        source_ip = ensure_valid_ip(req.source_ip)
        chosen_backend = ensure_valid_backend(backend, req.protocol)

        if action_idx == ACTION_KEEP_NORMAL:
            command = [str(ROUTING_SCRIPT), "remove_ip", source_ip]
        else:
            command = [str(ROUTING_SCRIPT), "add_ip", source_ip, chosen_backend]

    try:
        output = run_command(command)
    except subprocess.CalledProcessError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Failed to apply routing command",
                "command": " ".join(command),
                "stderr": (exc.stderr or "").strip(),
                "stdout": (exc.stdout or "").strip(),
            },
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504,
            detail={
                "message": "Routing command timed out",
                "command": " ".join(command),
                "timeout_seconds": COMMAND_TIMEOUT_SECONDS,
                "stdout": (exc.stdout or "").strip() if exc.stdout else "",
                "stderr": (exc.stderr or "").strip() if exc.stderr else "",
            },
        ) from exc

    return True, " ".join(command), output


def log_decision(req: DecisionRequest, action_idx: int, backend: str, applied: bool, route_output: Optional[str]) -> None:
    payload = {
        "event_schema_version": "1.0",
        "event_type": "route_decision",
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "routing-controller",
        "policy_mode": POLICY_MODE,
        "protocol": req.protocol,
        "session_id": req.session_id or "",
        "source_ip": req.source_ip or "",
        "action_id": action_idx,
        "action_name": action_name(action_idx),
        "backend": backend,
        "route_applied": applied,
        "route_output": route_output or "",
    }
    logger.info(json.dumps(payload, ensure_ascii=True))


def read_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    result: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0]] = parts[1]
    return result


def try_load_model(path: Path) -> tuple[bool, str]:
    global agent

    if not path.exists():
        agent = LinearQAgent(seed=123)
        return False, f"Model not found at {path}. Using untrained agent."

    with model_lock:
        agent = LinearQAgent.load(path)
    return True, f"Model loaded from {path}"


app = FastAPI(
    title="Adaptive Routing Controller",
    version="0.1.0",
    docs_url="/docs" if DEBUG_EXPOSURE else None,
    redoc_url="/redoc" if DEBUG_EXPOSURE else None,
    openapi_url="/openapi.json" if DEBUG_EXPOSURE else None,
)


@app.on_event("startup")
def startup() -> None:
    loaded, message = try_load_model(MODEL_PATH)
    logger.info("startup model_loaded=%s message=%s", loaded, message)


@app.get("/health")
def health() -> dict:
    if not DEBUG_EXPOSURE:
        return {"status": "ok"}

    return {
        "status": "ok",
        "exposure_mode": EXPOSURE_MODE,
        "model_path": str(MODEL_PATH),
        "routing_script": str(ROUTING_SCRIPT),
        "model_exists": MODEL_PATH.exists(),
        "policy_mode": POLICY_MODE,
        "heuristic_route_threshold": HEURISTIC_ROUTE_THRESHOLD,
        "l4_routing_enabled": L4_ROUTING_ENABLED,
        "implemented_backends": sorted(HTTP_BACKENDS),
    }


@app.post("/model/reload", response_model=ReloadModelResponse)
def reload_model() -> ReloadModelResponse:
    require_debug_exposure()
    loaded, message = try_load_model(MODEL_PATH)
    return ReloadModelResponse(loaded=loaded, model_path=str(MODEL_PATH), message=message)


@app.post("/route/session/{session_id}", response_model=RouteUpdateResponse)
def set_session_route(session_id: str, backend: str = Query(..., description="Target backend name")) -> RouteUpdateResponse:
    require_debug_exposure()
    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    chosen_backend = ensure_valid_backend(backend, "http")
    output = run_command([str(ROUTING_SCRIPT), "add_session", session_id, chosen_backend])
    return RouteUpdateResponse(
        status="ok",
        message=f"Session route updated: {session_id} -> {chosen_backend}",
        command=f"{ROUTING_SCRIPT} add_session {session_id} {chosen_backend}",
        output=output,
    )


@app.post("/route/ip/{source_ip}", response_model=RouteUpdateResponse)
def set_ip_route(source_ip: str, backend: str = Query(..., description="Target backend name")) -> RouteUpdateResponse:
    require_debug_exposure()
    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    safe_ip = ensure_valid_ip(source_ip)
    chosen_backend = ensure_valid_backend(backend, "http")
    output = run_command([str(ROUTING_SCRIPT), "add_ip", safe_ip, chosen_backend])
    return RouteUpdateResponse(
        status="ok",
        message=f"IP route updated: {safe_ip} -> {chosen_backend}",
        command=f"{ROUTING_SCRIPT} add_ip {safe_ip} {chosen_backend}",
        output=output,
    )


@app.post("/decide", response_model=DecisionResponse)
def decide(req: DecisionRequest) -> DecisionResponse:
    action_idx = select_policy_action(req)
    chosen_backend = action_backend(action_idx)
    applied, route_command, route_output = apply_route_decision(req, action_idx, chosen_backend)
    log_decision(req, action_idx, chosen_backend, applied, route_output)

    return DecisionResponse(
        protocol=req.protocol,
        action_id=action_idx,
        action_name=action_name(action_idx),
        backend=chosen_backend,
        route_applied=applied,
        route_command=route_command,
        route_output=route_output,
    )


@app.delete("/route/session/{session_id}")
def clear_session_route(session_id: str) -> dict:
    require_debug_exposure()
    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    output = run_command([str(ROUTING_SCRIPT), "remove_session", session_id])
    return {
        "status": "ok",
        "message": f"Session route removed: {session_id}",
        "output": output,
    }


@app.delete("/route/ip/{source_ip}")
def clear_ip_route(source_ip: str) -> dict:
    require_debug_exposure()
    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    safe_ip = ensure_valid_ip(source_ip)
    output = run_command([str(ROUTING_SCRIPT), "remove_ip", safe_ip])
    return {
        "status": "ok",
        "message": f"IP route removed: {safe_ip}",
        "output": output,
    }


@app.delete("/routes", response_model=ClearRoutesResponse)
def clear_routes() -> ClearRoutesResponse:
    require_debug_exposure()
    if not ROUTING_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Routing script not found: {ROUTING_SCRIPT}")

    command = [str(ROUTING_SCRIPT), "clear_all"]
    output = run_command(command)
    return ClearRoutesResponse(
        status="ok",
        message="All adaptive route maps cleared",
        command=" ".join(command),
        output=output,
    )


@app.get("/routes")
def list_routes() -> dict:
    require_debug_exposure()
    return {
        "status": "ok",
        "session_routes": read_map(SESSION_ROUTES_MAP),
        "ip_routes": read_map(IP_HONEYPOT_MAP),
    }


@app.get("/route/session/{session_id}")
def get_session_route(session_id: str) -> dict:
    require_debug_exposure()
    routes = read_map(SESSION_ROUTES_MAP)
    return {
        "status": "ok",
        "session_id": session_id,
        "backend": routes.get(session_id),
        "found": session_id in routes,
    }


@app.get("/route/ip/{source_ip}")
def get_ip_route(source_ip: str) -> dict:
    require_debug_exposure()
    safe_ip = ensure_valid_ip(source_ip)
    routes = read_map(IP_HONEYPOT_MAP)
    return {
        "status": "ok",
        "source_ip": safe_ip,
        "backend": routes.get(safe_ip),
        "found": safe_ip in routes,
    }
