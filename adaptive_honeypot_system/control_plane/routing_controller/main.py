"""
Routing Controller - FastAPI service for managing adaptive honeypot routing

Responsibilities:
- Receives RL Agent decisions
- Updates HAProxy routing tables
- Manages session/IP mappings
- Coordinates with LLM Analyzer
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List
import subprocess
import logging

app = FastAPI(title="Routing Controller")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RoutingAction(BaseModel):
    """RL Agent routing decision"""
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    target_backend: str  # e.g., 'sqli_pot', 'cmdi_pot', 'ssti_pot', 'ssrf_pot'
    protocol: str  # 'http', 'ssh', 'ftp', 'smtp'
    confidence: float  # 0.0-1.0

class StateReport(BaseModel):
    """State vector from LLM Analyzer"""
    session_id: Optional[str]
    ip_address: str
    attack_category: str  # injection, bruteforce, enumeration, malformed
    web_subtype_scores: List[float]  # [sqli, cmdi, ssti, ssrf]
    evasion_score: float
    llm_confidence: float
    protocol_detected: str

@app.post("/api/route")
def route_traffic(action: RoutingAction):
    """
    Apply routing decision from RL Agent
    
    For HTTP (L7): Update session_routes.map for mid-session rerouting
    For SSH/FTP/SMTP (L4): Update ip_honeypot.map and trigger connection drop
    """
    try:
        if action.protocol == "http":
            # L7 Session-based routing
            if not action.session_id:
                raise ValueError("session_id required for HTTP routing")
            
            # Update HAProxy session routing map
            _update_session_route(action.session_id, action.target_backend)
            logger.info(f"Session routing: {action.session_id} -> {action.target_backend} (conf: {action.confidence})")
            
            return {"status": "routing_applied", "type": "session", "target": action.target_backend}
        
        else:
            # L4 IP-based routing with connection drop
            if not action.ip_address:
                raise ValueError("ip_address required for L4 routing")
            
            # Update HAProxy IP routing map
            _update_ip_route(action.ip_address, action.target_backend)
            
            # Trigger TCP connection drop (connection pooling reset)
            _drop_connection(action.ip_address)
            logger.info(f"IP routing + drop: {action.ip_address} -> {action.target_backend} (cf: {action.confidence})")
            
            return {"status": "routing_applied", "type": "ip_drop", "target": action.target_backend}
    
    except Exception as e:
        logger.error(f"Routing error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/clear_routing")
def clear_routing(session_id: Optional[str] = None, ip_address: Optional[str] = None):
    """Remove routing decisions"""
    try:
        if session_id:
            _clear_session_route(session_id)
            logger.info(f"Session routing cleared: {session_id}")
        if ip_address:
            _clear_ip_route(ip_address)
            logger.info(f"IP routing cleared: {ip_address}")
        return {"status": "cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _update_session_route(session_id: str, backend: str):
    """Write to HAProxy session_routes.map"""
    with open("/etc/haproxy/maps/session_routes.map", "a") as f:
        f.write(f"{session_id} {backend}\n")

def _update_ip_route(ip: str, backend: str):
    """Write to HAProxy ip_honeypot.map"""
    with open("/etc/haproxy/maps/ip_honeypot.map", "a") as f:
        f.write(f"{ip} {backend}\n")

def _clear_session_route(session_id: str):
    """Remove session from map"""
    import subprocess
    subprocess.run(
        f"sed -i '/{session_id}/d' /etc/haproxy/maps/session_routes.map",
        shell=True, capture_output=True
    )

def _clear_ip_route(ip: str):
    """Remove IP from map"""
    import subprocess
    subprocess.run(
        f"sed -i '/{ip}/d' /etc/haproxy/maps/ip_honeypot.map",
        shell=True, capture_output=True
    )

def _drop_connection(ip: str):
    """Signal connection drop (L4 TCP RST)"""
    # This would be implemented via HAProxy admin socket or iptables rules
    # For now, log intent
    logger.info(f"[TCP RST] Preparing to drop connections from {ip}")

@app.get("/api/status")
def status():
    return {
        "service": "routing-controller",
        "status": "ready",
        "maps": {
            "session_routes": _count_lines("/etc/haproxy/maps/session_routes.map"),
            "ip_honeypot": _count_lines("/etc/haproxy/maps/ip_honeypot.map")
        }
    }

def _count_lines(filepath: str):
    try:
        with open(filepath) as f:
            return len(f.readlines())
    except:
        return 0

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
