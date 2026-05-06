from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

STATE_SCHEMA_VERSION = "rl_state_v2_16"

STATE_FIELD_NAMES = [
    "session_age_norm",
    "interaction_rate_norm",
    "failed_attempts_norm",
    "payload_complexity_norm",
    "target_diversity_norm",
    "current_route",
    "engagement_depth_norm",
    "target_sqli_score",
    "target_cmdi_score",
    "target_ssti_score",
    "target_ssrf_score",
    "target_credential_attack_score",
    "target_enumeration_score",
    "evasion_score",
    "attack_progression_stage",
    "intent_stability_score",
]

STATE_DIM = len(STATE_FIELD_NAMES)


def _clip01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class StateVector:
    session_age_norm: float = 0.0
    interaction_rate_norm: float = 0.0
    failed_attempts_norm: float = 0.0
    payload_complexity_norm: float = 0.0
    target_diversity_norm: float = 0.0
    current_route: float = 0.0
    engagement_depth_norm: float = 0.0
    target_sqli_score: float = 0.0
    target_cmdi_score: float = 0.0
    target_ssti_score: float = 0.0
    target_ssrf_score: float = 0.0
    target_credential_attack_score: float = 0.0
    target_enumeration_score: float = 0.0
    evasion_score: float = 0.0
    attack_progression_stage: float = 0.0
    intent_stability_score: float = 0.0

    def to_list(self) -> List[float]:
        return [
            _clip01(getattr(self, field_name))
            for field_name in STATE_FIELD_NAMES
        ]


def validate_state(values: Iterable[float]) -> List[float]:
    state = [float(value) for value in values]
    if len(state) != STATE_DIM:
        raise ValueError(f"Expected state dim {STATE_DIM}, got {len(state)}")
    return [_clip01(value) for value in state]
