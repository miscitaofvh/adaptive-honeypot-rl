from __future__ import annotations

import argparse
from pathlib import Path

from agent import (
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    LinearQAgent,
)


def build_dummy_web_policy_agent() -> LinearQAgent:
    """Create a deterministic model matching the proposal's web subtype order.

    The state vector uses subtype indices [13:17] = [sqli, cmdi, ssti, ssrf].
    This model keeps benign traffic normal and routes strong subtype evidence
    to the matching web honeypot. It is only a local demo stand-in for the
    future trained offline RL policy.
    """
    model = LinearQAgent(seed=0)
    model.weights = [[0.0 for _ in range(model.state_dim)] for _ in range(model.num_actions)]
    model.bias = [-1.0 for _ in range(model.num_actions)]

    model.bias[ACTION_KEEP_NORMAL] = 0.25
    model.bias[ACTION_ROUTE_SQLI] = 0.0
    model.bias[ACTION_ROUTE_CMDI] = 0.0
    model.bias[ACTION_ROUTE_SSTI] = 0.0
    model.bias[ACTION_ROUTE_SSRF] = 0.0

    model.weights[ACTION_ROUTE_SQLI][13] = 5.0
    model.weights[ACTION_ROUTE_CMDI][14] = 5.0
    model.weights[ACTION_ROUTE_SSTI][15] = 5.0
    model.weights[ACTION_ROUTE_SSRF][16] = 5.0

    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a deterministic dummy web policy model for SQLi/CMDI/SSTI/SSRF routing.",
    )
    parser.add_argument(
        "--output",
        default="control_plane/rl_agent/artifacts/rl_agent_linear.json",
        help="Path to output model JSON (default matches routing_controller model path)",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    model = build_dummy_web_policy_agent()
    model.save(output_path)

    print(f"Dummy web policy model saved to: {output_path}")
    print("HTTP behavior: subtype score [sqli, cmdi, ssti, ssrf] chooses matching web honeypot")
    print("Benign/low-score behavior: KEEP_NORMAL")


if __name__ == "__main__":
    main()
