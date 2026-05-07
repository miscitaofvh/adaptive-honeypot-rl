from __future__ import annotations

import json
import os
import random
import sys
import threading
import warnings
from pathlib import Path
from typing import Any, List, Optional

warnings.filterwarnings("ignore", message="Failed to initialize NumPy.*", category=UserWarning)

import torch
import torch.nn as nn
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

CONTROL_PLANE_DIR = Path(__file__).resolve().parents[1]
if str(CONTROL_PLANE_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE_DIR))

from agent import (  # noqa: E402
    ACTIONS,
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    allowed_action_indices,
    action_backend,
    action_name,
)
from state_builder import STATE_DIM, STATE_SCHEMA_VERSION, validate_state  # noqa: E402

EXPOSURE_MODE = os.getenv("EXPOSURE_MODE", "debug").strip().lower()
DEBUG_EXPOSURE = EXPOSURE_MODE in {"debug", "dev", "development", "operator", "test"}
MODEL_OUTPUT_PATH = Path(
    os.getenv(
        "RL_MODEL_OUTPUT_PATH",
        "/app/control_plane/rl_agent/artifacts/rl_agent_linear.json",
    )
)
INIT_MODE = os.getenv("RL_AGENT_INIT_MODE", "web_policy").strip().lower()
AUTO_EXPORT = os.getenv("RL_AGENT_AUTO_EXPORT", "false").strip().lower() in {"1", "true", "yes"}
SEED = int(os.getenv("RL_AGENT_SEED", "42"))

model_lock = threading.Lock()
torch.manual_seed(SEED)
random.seed(SEED)


class PredictRequest(BaseModel):
    state_schema: str = Field(default=STATE_SCHEMA_VERSION)
    protocol: str = Field(default="http")
    state: List[float] = Field(min_length=STATE_DIM, max_length=STATE_DIM)

    @field_validator("state_schema")
    @classmethod
    def validate_schema(cls, value: str) -> str:
        value = value.strip()
        if value != STATE_SCHEMA_VERSION:
            raise ValueError(f"state_schema must be {STATE_SCHEMA_VERSION}")
        return value

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"http", "ssh", "ftp", "smtp"}:
            raise ValueError("protocol must be one of: http, ssh, ftp, smtp")
        return value


class PredictResponse(BaseModel):
    state_schema: str
    protocol: str
    action_id: int
    action_name: str
    backend: str
    q_values: List[float]


class TrainOneEpochRequest(BaseModel):
    learning_rate: float = Field(default=0.01, gt=0.0, le=1.0)
    export_after: bool = True


class TrainOneEpochResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    status: str
    trained_epochs: int
    loss: float
    exported: bool
    model_path: Optional[str] = None


class ExportResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    status: str
    model_path: str
    state_schema: str
    state_dim: int
    init_mode: str


def require_debug_exposure() -> None:
    if not DEBUG_EXPOSURE:
        raise HTTPException(status_code=404, detail="Not found")


def build_model(init_mode: str) -> nn.Linear:
    model = nn.Linear(STATE_DIM, len(ACTIONS))
    with torch.no_grad():
        model.weight.zero_()
        model.bias.fill_(-1.0)

        # Low-risk default: deterministic web-subtype policy that mirrors the
        # existing dummy JSON model, while still being a real Torch module.
        if init_mode in {"web_policy", "dummy_web", "deterministic"}:
            model.bias[ACTION_KEEP_NORMAL] = 0.25
            model.bias[ACTION_ROUTE_SQLI] = 0.0
            model.bias[ACTION_ROUTE_CMDI] = 0.0
            model.bias[ACTION_ROUTE_SSTI] = 0.0
            model.bias[ACTION_ROUTE_SSRF] = 0.0
            model.weight[ACTION_ROUTE_SQLI, 7] = 5.0
            model.weight[ACTION_ROUTE_CMDI, 8] = 5.0
            model.weight[ACTION_ROUTE_SSTI, 9] = 5.0
            model.weight[ACTION_ROUTE_SSRF, 10] = 5.0
        elif init_mode in {"zero", "empty"}:
            model.bias[ACTION_KEEP_NORMAL] = 0.1
        else:
            raise ValueError("RL_AGENT_INIT_MODE must be web_policy or zero")
    return model


torch_model = build_model(INIT_MODE)
trained_epochs = 0
last_loss = 0.0


def model_payload(metadata: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    with torch.no_grad():
        payload = {
            "state_schema": STATE_SCHEMA_VERSION,
            "state_dim": STATE_DIM,
            "actions": ACTIONS,
            "weights": torch_model.weight.detach().cpu().tolist(),
            "bias": torch_model.bias.detach().cpu().tolist(),
            "metadata": {
                "source": "torch_rl_agent_service",
                "model": f"nn.Linear({STATE_DIM}, {len(ACTIONS)})",
                "init_mode": INIT_MODE,
                "trained_epochs": trained_epochs,
                "full_train": False,
            },
        }
    if metadata:
        payload["metadata"].update(metadata)
    return payload


def export_model(path: Path = MODEL_OUTPUT_PATH, metadata: Optional[dict[str, Any]] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(model_payload(metadata), f, indent=2)


def masked_prediction(state: list[float], protocol: str) -> tuple[int, list[float]]:
    with model_lock:
        with torch.no_grad():
            state_tensor = torch.tensor(validate_state(state), dtype=torch.float32).unsqueeze(0)
            q_values = torch_model(state_tensor).squeeze(0)
            masked = torch.full_like(q_values, -1e9)
            for action_idx in allowed_action_indices(protocol):
                masked[action_idx] = q_values[action_idx]
            action_idx = int(masked.argmax().item())
            return action_idx, q_values.detach().cpu().tolist()


def one_epoch_proxy_train(learning_rate: float) -> float:
    """One tiny epoch over deterministic proxy samples. This is not full RL training."""
    global trained_epochs, last_loss

    samples = [
        ([0, 0, 0, 0, 0, 0, 0, 0.95, 0.02, 0.02, 0.02, 0, 0, 0.2, 0.4, 0.8], ACTION_ROUTE_SQLI),
        ([0, 0, 0, 0, 0, 0, 0, 0.02, 0.95, 0.02, 0.02, 0, 0, 0.2, 0.4, 0.8], ACTION_ROUTE_CMDI),
        ([0, 0, 0, 0, 0, 0, 0, 0.02, 0.02, 0.95, 0.02, 0, 0, 0.2, 0.4, 0.8], ACTION_ROUTE_SSTI),
        ([0, 0, 0, 0, 0, 0, 0, 0.02, 0.02, 0.02, 0.95, 0, 0, 0.2, 0.4, 0.8], ACTION_ROUTE_SSRF),
        ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ACTION_KEEP_NORMAL),
    ]

    optimizer = torch.optim.SGD(torch_model.parameters(), lr=learning_rate)
    states = torch.tensor([state for state, _ in samples], dtype=torch.float32)
    targets = torch.tensor([action for _, action in samples], dtype=torch.long)

    with model_lock:
        torch_model.train()
        optimizer.zero_grad()
        logits = torch_model(states)
        loss = F.cross_entropy(logits, targets)
        loss.backward()
        optimizer.step()
        trained_epochs += 1
        last_loss = float(loss.item())
        torch_model.eval()
    return last_loss


app = FastAPI(
    title="Torch RL Agent",
    version="0.1.0",
    docs_url="/docs" if DEBUG_EXPOSURE else None,
    redoc_url="/redoc" if DEBUG_EXPOSURE else None,
    openapi_url="/openapi.json" if DEBUG_EXPOSURE else None,
)


@app.on_event("startup")
def startup() -> None:
    if AUTO_EXPORT:
        export_model(metadata={"auto_export": True})


@app.get("/health")
def health() -> dict[str, Any]:
    if not DEBUG_EXPOSURE:
        return {"status": "ok"}
    return {
        "status": "ok",
        "exposure_mode": EXPOSURE_MODE,
        "state_schema": STATE_SCHEMA_VERSION,
        "state_dim": STATE_DIM,
        "torch_version": torch.__version__,
        "init_mode": INIT_MODE,
        "trained_epochs": trained_epochs,
        "last_loss": last_loss,
        "model_output_path": str(MODEL_OUTPUT_PATH),
        "auto_export": AUTO_EXPORT,
    }


@app.get("/model/info")
def model_info() -> dict[str, Any]:
    require_debug_exposure()
    return model_payload(metadata={"last_loss": last_loss})["metadata"] | {
        "state_schema": STATE_SCHEMA_VERSION,
        "state_dim": STATE_DIM,
        "actions": ACTIONS,
        "model_output_path": str(MODEL_OUTPUT_PATH),
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> PredictResponse:
    require_debug_exposure()
    action_idx, q_values = masked_prediction(req.state, req.protocol)
    return PredictResponse(
        state_schema=req.state_schema,
        protocol=req.protocol,
        action_id=action_idx,
        action_name=action_name(action_idx),
        backend=action_backend(action_idx),
        q_values=q_values,
    )


@app.post("/train/one-epoch", response_model=TrainOneEpochResponse)
def train_one_epoch(req: TrainOneEpochRequest) -> TrainOneEpochResponse:
    require_debug_exposure()
    loss = one_epoch_proxy_train(req.learning_rate)
    exported = False
    if req.export_after:
        export_model(metadata={"trained_by_endpoint": "/train/one-epoch", "last_loss": loss})
        exported = True
    return TrainOneEpochResponse(
        status="ok",
        trained_epochs=trained_epochs,
        loss=loss,
        exported=exported,
        model_path=str(MODEL_OUTPUT_PATH) if exported else None,
    )


@app.post("/export", response_model=ExportResponse)
def export_endpoint() -> ExportResponse:
    require_debug_exposure()
    export_model(metadata={"exported_by_endpoint": "/export", "last_loss": last_loss})
    return ExportResponse(
        status="ok",
        model_path=str(MODEL_OUTPUT_PATH),
        state_schema=STATE_SCHEMA_VERSION,
        state_dim=STATE_DIM,
        init_mode=INIT_MODE,
    )
