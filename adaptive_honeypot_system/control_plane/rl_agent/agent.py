from __future__ import annotations

import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

CONTROL_PLANE_DIR = Path(__file__).resolve().parents[1]

if str(CONTROL_PLANE_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE_DIR))

from state_builder import STATE_DIM, STATE_SCHEMA_VERSION, validate_state  # noqa: E402

PROTOCOLS = ("http", "ssh", "ftp", "smtp")

ACTION_KEEP_NORMAL = 0
ACTION_ROUTE_SQLI = 1
ACTION_ROUTE_SSTI = 2
ACTION_ROUTE_CMDI = 3
ACTION_ROUTE_SSRF = 4
ACTION_ROUTE_SSH = 5
ACTION_ROUTE_FTP = 6
ACTION_ROUTE_SMTP = 7

ACTIONS = [
    "KEEP_NORMAL",
    "ROUTE_SQLI",
    "ROUTE_SSTI",
    "ROUTE_CMDI",
    "ROUTE_SSRF",
    "ROUTE_SSH",
    "ROUTE_FTP",
    "ROUTE_SMTP",
]

ACTION_TO_BACKEND = {
    ACTION_KEEP_NORMAL: "normal_api",
    ACTION_ROUTE_SQLI: "sqli_api",
    ACTION_ROUTE_SSTI: "ssti_api",
    ACTION_ROUTE_CMDI: "cmdi_api",
    ACTION_ROUTE_SSRF: "ssrf_api",
    ACTION_ROUTE_SSH: "ssh_honeypot",
    ACTION_ROUTE_FTP: "ftp_honeypot",
    ACTION_ROUTE_SMTP: "smtp_honeypot",
}

_ALLOWED_BY_PROTOCOL = {
    "http": [
        ACTION_KEEP_NORMAL,
        ACTION_ROUTE_SQLI,
        ACTION_ROUTE_SSTI,
        ACTION_ROUTE_CMDI,
        ACTION_ROUTE_SSRF,
    ],
    "ssh": [ACTION_KEEP_NORMAL, ACTION_ROUTE_SSH],
    "ftp": [ACTION_KEEP_NORMAL, ACTION_ROUTE_FTP],
    "smtp": [ACTION_KEEP_NORMAL, ACTION_ROUTE_SMTP],
}


@dataclass
class Transition:
    state: List[float]
    action: int
    reward: float
    next_state: List[float]
    done: bool
    protocol: str = "http"
    optimal_action: Optional[int] = None


def clip(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def protocol_from_state(state: Sequence[float]) -> str:
    # State schema v2 intentionally keeps protocol out of the tensor.
    # Callers should pass transition.protocol; this fallback preserves older
    # datasets without protocol metadata as HTTP.
    return "http"


def allowed_action_indices(protocol: str) -> List[int]:
    return list(_ALLOWED_BY_PROTOCOL.get(protocol.lower(), _ALLOWED_BY_PROTOCOL["http"]))


def action_name(action_idx: int) -> str:
    if 0 <= action_idx < len(ACTIONS):
        return ACTIONS[action_idx]
    return f"UNKNOWN_{action_idx}"


def action_backend(action_idx: int) -> str:
    return ACTION_TO_BACKEND.get(action_idx, "normal_api")


class LinearQAgent:
    def __init__(
        self,
        state_dim: int = STATE_DIM,
        action_space: Optional[Sequence[str]] = None,
        seed: int = 42,
        init_scale: float = 0.02,
    ) -> None:
        self.state_dim = state_dim
        self.action_space = list(action_space or ACTIONS)
        self.num_actions = len(self.action_space)

        rng = random.Random(seed)
        self.weights: List[List[float]] = [
            [rng.uniform(-init_scale, init_scale) for _ in range(self.state_dim)]
            for _ in range(self.num_actions)
        ]
        self.bias: List[float] = [0.0 for _ in range(self.num_actions)]

    def q_values(self, state: Sequence[float]) -> List[float]:
        if len(state) != self.state_dim:
            raise ValueError(f"Expected state dim {self.state_dim}, got {len(state)}")

        values: List[float] = []
        for action_idx in range(self.num_actions):
            row = self.weights[action_idx]
            q_val = self.bias[action_idx]
            for i in range(self.state_dim):
                q_val += row[i] * float(state[i])
            values.append(q_val)
        return values

    def select_action(
        self,
        state: Sequence[float],
        protocol: str,
        epsilon: float = 0.0,
        rng: Optional[random.Random] = None,
    ) -> Tuple[int, List[float]]:
        q_vals = self.q_values(state)
        allowed = allowed_action_indices(protocol)

        local_rng = rng or random
        if epsilon > 0.0 and local_rng.random() < epsilon:
            return local_rng.choice(allowed), q_vals

        best_action = max(allowed, key=lambda idx: q_vals[idx])
        return best_action, q_vals

    def update_transition(
        self,
        transition: Transition,
        gamma: float,
        learning_rate: float,
        l2_weight_decay: float,
        grad_clip: float = 10.0,
    ) -> float:
        state = transition.state
        next_state = transition.next_state
        action = int(transition.action)

        if not (0 <= action < self.num_actions):
            return 0.0

        q_now = self.q_values(state)
        pred_q = q_now[action]

        if transition.done:
            target_q = transition.reward
        else:
            next_allowed = allowed_action_indices(transition.protocol)
            q_next = self.q_values(next_state)
            max_next = max(q_next[idx] for idx in next_allowed)
            target_q = transition.reward + gamma * max_next

        td_error = pred_q - target_q

        row = self.weights[action]
        for i in range(self.state_dim):
            grad = td_error * state[i] + l2_weight_decay * row[i]
            grad = clip(grad, -grad_clip, grad_clip)
            row[i] -= learning_rate * grad

        self.bias[action] -= learning_rate * clip(td_error, -grad_clip, grad_clip)
        return td_error * td_error

    def train_epoch(
        self,
        transitions: Sequence[Transition],
        gamma: float,
        learning_rate: float,
        l2_weight_decay: float,
        seed: int,
    ) -> float:
        if not transitions:
            return 0.0

        indices = list(range(len(transitions)))
        random.Random(seed).shuffle(indices)

        mse_total = 0.0
        for idx in indices:
            mse_total += self.update_transition(
                transitions[idx],
                gamma=gamma,
                learning_rate=learning_rate,
                l2_weight_decay=l2_weight_decay,
            )

        return mse_total / float(len(indices))

    def to_dict(self) -> Dict[str, object]:
        return {
            "state_schema": STATE_SCHEMA_VERSION,
            "state_dim": self.state_dim,
            "actions": self.action_space,
            "weights": self.weights,
            "bias": self.bias,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "LinearQAgent":
        state_dim = int(data["state_dim"])
        actions = list(data["actions"])
        agent = cls(state_dim=state_dim, action_space=actions)
        agent.weights = [list(map(float, row)) for row in data["weights"]]
        agent.bias = [float(v) for v in data["bias"]]
        return agent

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> "LinearQAgent":
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


def parse_transition(raw: Dict[str, object]) -> Transition:
    state = validate_state(raw["state"])
    next_state = validate_state(raw["next_state"])

    protocol = str(raw.get("protocol") or protocol_from_state(state)).lower()
    optimal_action = raw.get("optimal_action")
    if optimal_action is not None:
        optimal_action = int(optimal_action)

    return Transition(
        state=state,
        action=int(raw["action"]),
        reward=float(raw["reward"]),
        next_state=next_state,
        done=bool(raw["done"]),
        protocol=protocol,
        optimal_action=optimal_action,
    )


def load_transitions(path: str | Path) -> List[Transition]:
    transitions: List[Transition] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            transitions.append(parse_transition(raw))
    return transitions
