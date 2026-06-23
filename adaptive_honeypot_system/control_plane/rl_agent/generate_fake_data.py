from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

from agent import (
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    STATE_DIM,
    action_backend,
    action_name,
    allowed_action_indices,
)
from state_builder import STATE_FIELD_NAMES, STATE_SCHEMA_VERSION

HTTP_ATTACKS = ["benign", "sqli", "cmdi", "ssti", "ssrf", "malformed"]


def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def weighted_choice(rng: random.Random, choices: List[Tuple[str, float]]) -> str:
    total = sum(weight for _, weight in choices)
    ticket = rng.random() * total
    running = 0.0
    for item, weight in choices:
        running += weight
        if ticket <= running:
            return item
    return choices[-1][0]


def choose_protocol(rng: random.Random) -> str:
    return "http"


def choose_attack(rng: random.Random, protocol: str, previous_attack: str | None) -> str:
    if previous_attack and rng.random() < 0.55:
        return previous_attack

    if protocol == "http":
        return weighted_choice(
            rng,
            [
                ("benign", 0.38),
                ("sqli", 0.16),
                ("cmdi", 0.15),
                ("ssti", 0.14),
                ("ssrf", 0.12),
                ("malformed", 0.05),
            ],
        )
    return "benign"


def optimal_action(protocol: str, attack: str) -> int:
    if protocol == "http":
        if attack == "sqli":
            return ACTION_ROUTE_SQLI
        if attack == "cmdi":
            return ACTION_ROUTE_CMDI
        if attack == "ssti":
            return ACTION_ROUTE_SSTI
        if attack == "ssrf":
            return ACTION_ROUTE_SSRF
        return ACTION_KEEP_NORMAL

    return ACTION_KEEP_NORMAL


def choose_behavior_action(
    rng: random.Random,
    protocol: str,
    attack: str,
    optimal: int,
) -> int:
    allowed = allowed_action_indices(protocol)

    if attack == "benign":
        if rng.random() < 0.90:
            return ACTION_KEEP_NORMAL
        noisy_choices = [idx for idx in allowed if idx != ACTION_KEEP_NORMAL]
        return rng.choice(noisy_choices) if noisy_choices else ACTION_KEEP_NORMAL

    roll = rng.random()
    if roll < 0.70:
        return optimal
    if roll < 0.84:
        return ACTION_KEEP_NORMAL

    alternatives = [idx for idx in allowed if idx != optimal]
    return rng.choice(alternatives) if alternatives else optimal


def reward_for_action(action: int, optimal: int, attack: str, current_route: int, rng: random.Random) -> float:
    if optimal == ACTION_KEEP_NORMAL:
        reward = 0.45 if action == ACTION_KEEP_NORMAL else -1.45
    else:
        if action == optimal:
            reward = 2.10 if current_route == 0 else 1.55
        elif action == ACTION_KEEP_NORMAL:
            reward = -0.95
        else:
            reward = -1.30

    if attack == "benign" and action != ACTION_KEEP_NORMAL:
        reward -= 0.20

    reward += rng.uniform(-0.12, 0.12)
    return round(reward, 4)


def target_scores(protocol: str, attack: str) -> List[float]:
    """Return v2 target scores:
    [sqli, cmdi, ssti, ssrf, credential_attack_reserved, enumeration_reserved].
    """
    scores = [0.0 for _ in range(6)]
    if protocol == "http":
        mapping = {"sqli": 0, "cmdi": 1, "ssti": 2, "ssrf": 3}
        if attack in mapping:
            scores[mapping[attack]] = 0.94
            for idx in range(4):
                if idx != mapping[attack]:
                    scores[idx] = 0.02
    return scores


def make_state(
    rng: random.Random,
    protocol: str,
    attack: str,
    step: int,
    total_steps: int,
    current_route: int,
    previous_attack: str | None,
) -> List[float]:
    malicious = attack != "benign"

    session_age_norm = clip01(step / max(1.0, float(total_steps - 1)))

    interaction_rate_norm = rng.uniform(0.18, 0.58)
    if malicious:
        interaction_rate_norm += rng.uniform(0.14, 0.30)

    failed_attempts_norm = rng.uniform(0.0, 0.20)
    if malicious:
        failed_attempts_norm += rng.uniform(0.40, 0.75)

    payload_complexity_norm = rng.uniform(0.04, 0.25)
    if attack in {"sqli", "cmdi", "ssti", "ssrf", "malformed"}:
        payload_complexity_norm += rng.uniform(0.30, 0.62)
    if attack == "bruteforce":
        payload_complexity_norm += rng.uniform(0.08, 0.20)

    target_diversity_norm = rng.uniform(0.10, 0.35)
    if attack == "enumeration":
        target_diversity_norm += rng.uniform(0.35, 0.52)

    llm_confidence = rng.uniform(0.55, 0.84)
    if malicious:
        llm_confidence += rng.uniform(0.08, 0.14)
    llm_confidence = clip01(llm_confidence)

    effective_targets = [clip01(v * llm_confidence) for v in target_scores(protocol, attack)]

    evasion_score = rng.uniform(0.05, 0.22)
    if malicious:
        evasion_score += rng.uniform(0.24, 0.58)
    effective_evasion = clip01(evasion_score * llm_confidence)

    attack_vector_shift = 0.0
    if previous_attack and previous_attack != attack:
        attack_vector_shift = rng.uniform(0.48, 0.95)
    elif previous_attack:
        attack_vector_shift = rng.uniform(0.01, 0.22)

    historical_intent_consistency = rng.uniform(0.36, 0.68)
    if previous_attack and previous_attack == attack:
        historical_intent_consistency += rng.uniform(0.14, 0.26)

    attack_progression_stage = clip01(0.18 + session_age_norm * 0.66 + rng.uniform(-0.06, 0.10))
    intent_shift_velocity = clip01(attack_vector_shift * rng.uniform(0.35, 0.90))
    intent_stability_score = clip01(
        historical_intent_consistency * (1.0 - intent_shift_velocity) * llm_confidence
    )
    engagement_depth_norm = 0.0
    if current_route:
        engagement_depth_norm = clip01(0.20 + session_age_norm * 0.55 + rng.uniform(0.0, 0.20))

    state = [
        session_age_norm,
        clip01(interaction_rate_norm),
        clip01(failed_attempts_norm),
        clip01(payload_complexity_norm),
        clip01(target_diversity_norm),
        float(current_route),
        engagement_depth_norm,
        *effective_targets,
        effective_evasion,
        clip01(attack_progression_stage * llm_confidence),
        intent_stability_score,
    ]

    if len(state) != STATE_DIM:
        raise ValueError(f"Expected state dim {STATE_DIM}, got {len(state)}")

    return [round(float(v), 6) for v in state]


def generate_dataset(
    output_path: Path,
    sessions: int,
    min_steps: int,
    max_steps: int,
    seed: int,
) -> Dict[str, Dict[str, int]]:
    rng = random.Random(seed)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    protocol_counter: Counter[str] = Counter()
    attack_counter: Counter[str] = Counter()
    optimal_action_counter: Counter[int] = Counter()

    transition_count = 0

    with output_path.open("w", encoding="utf-8") as f:
        for session_idx in range(sessions):
            protocol = choose_protocol(rng)
            steps = rng.randint(min_steps, max_steps)

            protocol_counter[protocol] += 1

            current_route = 0
            current_attack = choose_attack(rng, protocol, previous_attack=None)
            previous_attack = None

            for step in range(steps):
                state = make_state(
                    rng=rng,
                    protocol=protocol,
                    attack=current_attack,
                    step=step,
                    total_steps=steps,
                    current_route=current_route,
                    previous_attack=previous_attack,
                )

                best_action = optimal_action(protocol, current_attack)
                behavior_action = choose_behavior_action(rng, protocol, current_attack, best_action)

                reward = reward_for_action(
                    behavior_action,
                    best_action,
                    current_attack,
                    current_route,
                    rng,
                )

                done = step == (steps - 1)
                next_route = 0 if behavior_action == ACTION_KEEP_NORMAL else 1

                next_attack = current_attack if done else choose_attack(rng, protocol, previous_attack=current_attack)
                next_state = make_state(
                    rng=rng,
                    protocol=protocol,
                    attack=next_attack,
                    step=min(step + 1, steps - 1),
                    total_steps=steps,
                    current_route=next_route,
                    previous_attack=current_attack,
                )

                payload = {
                    "session_id": f"session_{session_idx:05d}",
                    "source": "generated",
                    "step": step,
                    "protocol": protocol,
                    "attack_type": current_attack,
                    "state_schema": STATE_SCHEMA_VERSION,
                    "state_fields": STATE_FIELD_NAMES,
                    "state": state,
                    "action": behavior_action,
                    "action_name": action_name(behavior_action),
                    "backend": action_backend(behavior_action),
                    "reward": reward,
                    "next_state": next_state,
                    "done": done,
                    "optimal_action": best_action,
                }
                f.write(json.dumps(payload) + "\n")

                transition_count += 1
                attack_counter[current_attack] += 1
                optimal_action_counter[best_action] += 1

                previous_attack = current_attack
                current_attack = next_attack
                current_route = next_route

    return {
        "summary": {
            "sessions": sessions,
            "transitions": transition_count,
        },
        "protocol_counts": dict(protocol_counter),
        "attack_counts": dict(attack_counter),
        "optimal_action_counts": {str(k): v for k, v in optimal_action_counter.items()},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate transitions for offline RL training.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "fake_transitions.jsonl",
        help="Output JSONL dataset path.",
    )
    parser.add_argument("--sessions", type=int, default=10000, help="Number of generated sessions.")
    parser.add_argument("--min-steps", type=int, default=8, help="Minimum steps per session.")
    parser.add_argument("--max-steps", type=int, default=12, help="Maximum steps per session.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.min_steps < 2:
        raise ValueError("--min-steps must be >= 2")
    if args.max_steps < args.min_steps:
        raise ValueError("--max-steps must be >= --min-steps")

    stats = generate_dataset(
        output_path=args.output,
        sessions=args.sessions,
        min_steps=args.min_steps,
        max_steps=args.max_steps,
        seed=args.seed,
    )

    print("Generated dataset ready")
    print(f"- Output: {args.output}")
    print(f"- Sessions: {stats['summary']['sessions']}")
    print(f"- Transitions: {stats['summary']['transitions']}")
    print(f"- Protocol counts: {stats['protocol_counts']}")
    print(f"- Attack counts: {stats['attack_counts']}")
    print(f"- Optimal action counts: {stats['optimal_action_counts']}")


if __name__ == "__main__":
    main()
