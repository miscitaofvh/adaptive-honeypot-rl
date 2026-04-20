from __future__ import annotations

import argparse
from pathlib import Path

from agent import ACTION_KEEP_NORMAL, ACTION_ROUTE_SSTI, LinearQAgent


def build_dummy_ssti_agent() -> LinearQAgent:
    """Create a deterministic agent that always chooses SSTI for HTTP states."""
    model = LinearQAgent(seed=0)

    model.weights = [[0.0 for _ in range(model.state_dim)] for _ in range(model.num_actions)]
    model.bias = [-1.0 for _ in range(model.num_actions)]

    # Non-HTTP protocols only expose KEEP + protocol-specific action via masking.
    model.bias[ACTION_KEEP_NORMAL] = 0.0
    # HTTP masking includes ROUTE_SSTI, so it wins regardless of state values.
    model.bias[ACTION_ROUTE_SSTI] = 10.0

    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a dummy RL model that routes any HTTP input to SSTI honeypot.",
    )
    parser.add_argument(
        "--output",
        default="control_plane/rl_agent/artifacts/rl_agent_linear.json",
        help="Path to output model JSON (default matches routing_controller model path)",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    model = build_dummy_ssti_agent()
    model.save(output_path)

    print(f"Dummy model saved to: {output_path}")
    print("HTTP behavior: always ROUTE_SSTI")
    print("Non-HTTP behavior: KEEP_NORMAL (via action masking)")


if __name__ == "__main__":
    main()
