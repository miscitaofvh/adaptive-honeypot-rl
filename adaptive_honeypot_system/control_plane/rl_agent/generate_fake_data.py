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
    ACTION_ROUTE_FTP,
    ACTION_ROUTE_SMTP,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSH,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    STATE_DIM,
    allowed_action_indices,
)

HTTP_ATTACKS = ["benign", "sqli", "cmdi", "ssti", "ssrf", "malformed"]
SSH_ATTACKS = ["benign", "bruteforce", "enumeration"]
FTP_ATTACKS = ["benign", "bruteforce", "enumeration"]
SMTP_ATTACKS = ["benign", "bruteforce", "enumeration"]


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
    return weighted_choice(
        rng,
        [
            ("http", 0.72),
            ("ssh", 0.10),
            ("ftp", 0.10),
            ("smtp", 0.08),
        ],
    )


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
    if protocol == "ssh":
        return weighted_choice(rng, [("benign", 0.48), ("bruteforce", 0.36), ("enumeration", 0.16)])
    if protocol == "ftp":
        return weighted_choice(rng, [("benign", 0.50), ("bruteforce", 0.28), ("enumeration", 0.22)])
    return weighted_choice(rng, [("benign", 0.52), ("bruteforce", 0.32), ("enumeration", 0.16)])


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

    if protocol == "ssh":
        return ACTION_KEEP_NORMAL if attack == "benign" else ACTION_ROUTE_SSH
    if protocol == "ftp":
        return ACTION_KEEP_NORMAL if attack == "benign" else ACTION_ROUTE_FTP
    if protocol == "smtp":
        return ACTION_KEEP_NORMAL if attack == "benign" else ACTION_ROUTE_SMTP

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


def attack_category_and_subtype(protocol: str, attack: str) -> Tuple[List[float], List[float]]:
    category = [0.0, 0.0, 0.0, 0.0]  # injection, bruteforce, enumeration, malformed
    subtype = [0.0, 0.0, 0.0, 0.0]  # sqli, cmdi, ssti, ssrf

    if protocol == "http":
        if attack in {"sqli", "cmdi", "ssti", "ssrf"}:
            category[0] = 1.0
        elif attack == "malformed":
            category[3] = 1.0

        if attack == "sqli":
            subtype = [0.92, 0.03, 0.03, 0.02]
        elif attack == "cmdi":
            subtype = [0.03, 0.92, 0.03, 0.02]
        elif attack == "ssti":
            subtype = [0.03, 0.02, 0.93, 0.02]
        elif attack == "ssrf":
            subtype = [0.02, 0.02, 0.02, 0.94]
        else:
            subtype = [0.05, 0.05, 0.05, 0.05]
    else:
        if attack == "bruteforce":
            category[1] = 1.0
        elif attack == "enumeration":
            category[2] = 1.0

    return category, subtype


def make_state(
    rng: random.Random,
    protocol: str,
    attack: str,
    step: int,
    total_steps: int,
    current_route: int,
    previous_attack: str | None,
) -> List[float]:
    protocol_onehot = [0.0, 0.0, 0.0, 0.0]
    protocol_index = {"http": 0, "ssh": 1, "ftp": 2, "smtp": 3}[protocol]
    protocol_onehot[protocol_index] = 1.0

    malicious = attack != "benign"

    session_age_norm = clip01(step / max(1.0, float(total_steps - 1)))

    interaction_rate_norm = rng.uniform(0.18, 0.58)
    if malicious:
        interaction_rate_norm += rng.uniform(0.14, 0.30)

    failed_attempts_norm = rng.uniform(0.0, 0.20)
    if malicious:
        failed_attempts_norm += rng.uniform(0.40, 0.75)

    content_size_anomaly = rng.uniform(0.04, 0.25)
    if attack in {"sqli", "cmdi", "ssti", "ssrf", "malformed"}:
        content_size_anomaly += rng.uniform(0.30, 0.62)

    probe_diversity_norm = rng.uniform(0.10, 0.35)
    if attack == "enumeration":
        probe_diversity_norm += rng.uniform(0.35, 0.52)

    category, subtype = attack_category_and_subtype(protocol, attack)

    llm_confidence = rng.uniform(0.55, 0.84)
    if malicious:
        llm_confidence += rng.uniform(0.08, 0.14)
    llm_confidence = clip01(llm_confidence)

    effective_category = [clip01(v * llm_confidence) for v in category]
    effective_subtype = [clip01(v * llm_confidence) for v in subtype]

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
    memory_decay_weight = clip01(1.0 - 0.03 * step + rng.uniform(-0.04, 0.03))
    intent_shift_velocity = clip01(attack_vector_shift * rng.uniform(0.35, 0.90))

    state = (
        protocol_onehot
        + [
            clip01(interaction_rate_norm),
            clip01(failed_attempts_norm),
            clip01(content_size_anomaly),
            clip01(probe_diversity_norm),
        ]
        + effective_category
        + effective_subtype
        + [
            effective_evasion,
            float(current_route),
            clip01(attack_vector_shift),
            clip01(historical_intent_consistency),
            attack_progression_stage,
            memory_decay_weight,
            intent_shift_velocity,
        ]
    )

    # Insert session_age_norm at index 4 according to the intended 24D schema.
    state.insert(4, session_age_norm)

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
                    "step": step,
                    "protocol": protocol,
                    "attack_type": current_attack,
                    "state": state,
                    "action": behavior_action,
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
    parser = argparse.ArgumentParser(description="Generate fake transitions for offline RL training.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "fake_transitions.jsonl",
        help="Output JSONL dataset path.",
    )
    parser.add_argument("--sessions", type=int, default=800, help="Number of synthetic sessions.")
    parser.add_argument("--min-steps", type=int, default=6, help="Minimum steps per session.")
    parser.add_argument("--max-steps", type=int, default=14, help="Maximum steps per session.")
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

    print("Fake dataset generated")
    print(f"- Output: {args.output}")
    print(f"- Sessions: {stats['summary']['sessions']}")
    print(f"- Transitions: {stats['summary']['transitions']}")
    print(f"- Protocol counts: {stats['protocol_counts']}")
    print(f"- Attack counts: {stats['attack_counts']}")
    print(f"- Optimal action counts: {stats['optimal_action_counts']}")


if __name__ == "__main__":
    main()
