from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

from agent import (
    ACTIONS,
    ACTION_KEEP_NORMAL,
    ACTION_ROUTE_CMDI,
    ACTION_ROUTE_SQLI,
    ACTION_ROUTE_SSRF,
    ACTION_ROUTE_SSTI,
    STATE_DIM,
    STATE_SCHEMA_VERSION,
    Transition,
    allowed_action_indices,
    action_name,
    load_transitions,
)

SUPPORTED_ALGORITHMS = ("cql", "q_learning")


def split_dataset(
    transitions: Sequence[Transition],
    validation_ratio: float,
    seed: int,
) -> Tuple[List[Transition], List[Transition]]:
    idx = list(range(len(transitions)))
    random.Random(seed).shuffle(idx)

    split_at = int((1.0 - validation_ratio) * len(idx))
    train_idx = idx[:split_at]
    val_idx = idx[split_at:]

    train_set = [transitions[i] for i in train_idx]
    val_set = [transitions[i] for i in val_idx]
    return train_set, val_set


def proxy_reward(pred_action: int, optimal_action: int) -> float:
    if optimal_action == ACTION_KEEP_NORMAL:
        return 0.40 if pred_action == ACTION_KEEP_NORMAL else -1.25
    if pred_action == optimal_action:
        return 1.80
    if pred_action == ACTION_KEEP_NORMAL:
        return -0.90
    return -1.20


def build_current_action_mask(transitions: Sequence[Transition]) -> torch.Tensor:
    mask = torch.zeros((len(transitions), len(ACTIONS)), dtype=torch.bool)
    for idx, transition in enumerate(transitions):
        for action_idx in allowed_action_indices(transition.protocol):
            mask[idx, action_idx] = True
    return mask


def build_next_action_mask(transitions: Sequence[Transition]) -> torch.Tensor:
    mask = torch.zeros((len(transitions), len(ACTIONS)), dtype=torch.bool)
    for idx, transition in enumerate(transitions):
        for action_idx in allowed_action_indices(transition.protocol):
            mask[idx, action_idx] = True
    return mask


def to_tensors(transitions: Sequence[Transition], device: torch.device) -> Dict[str, torch.Tensor]:
    states = torch.tensor([t.state for t in transitions], dtype=torch.float32, device=device)
    actions = torch.tensor([t.action for t in transitions], dtype=torch.int64, device=device)
    rewards = torch.tensor([t.reward for t in transitions], dtype=torch.float32, device=device)
    next_states = torch.tensor([t.next_state for t in transitions], dtype=torch.float32, device=device)
    dones = torch.tensor([1.0 if t.done else 0.0 for t in transitions], dtype=torch.float32, device=device)
    current_mask = build_current_action_mask(transitions).to(device)
    next_mask = build_next_action_mask(transitions).to(device)

    return {
        "states": states,
        "actions": actions,
        "rewards": rewards,
        "next_states": next_states,
        "dones": dones,
        "current_mask": current_mask,
        "next_mask": next_mask,
    }


def conservative_q_regularizer(
    q_values: torch.Tensor,
    actions: torch.Tensor,
    current_mask: torch.Tensor,
    temperature: float,
) -> torch.Tensor:
    """Discrete CQL penalty: lower unseen/action-alternative Q values.

    The dataset action should stay valuable, but the model is penalized when it
    assigns high Q to other valid actions for the same protocol. This is the
    practical offline-RL guardrail missing from plain fitted Q-learning.
    """
    q_selected = q_values.gather(1, actions.unsqueeze(1)).squeeze(1)
    masked_q = q_values.masked_fill(~current_mask, -1e9)
    conservative_value = torch.logsumexp(masked_q / temperature, dim=1) * temperature
    return (conservative_value - q_selected).mean()


def evaluate(model: nn.Module, transitions: Sequence[Transition], device: torch.device) -> Dict[str, float]:
    if not transitions:
        return {
            "accuracy": 0.0,
            "avg_proxy_reward": 0.0,
            "samples": 0,
        }

    with torch.no_grad():
        tensors = to_tensors(transitions, device)
        q_values = model(tensors["states"])
        masked_q = q_values.masked_fill(~tensors["current_mask"], -1e9)
        predicted = masked_q.argmax(dim=1).detach().cpu().tolist()

    correct = 0
    total = 0
    reward_sum = 0.0

    for idx, transition in enumerate(transitions):
        if transition.optimal_action is None:
            continue
        pred_action = int(predicted[idx])
        total += 1
        if pred_action == transition.optimal_action:
            correct += 1
        reward_sum += proxy_reward(pred_action, transition.optimal_action)

    if total == 0:
        return {
            "accuracy": 0.0,
            "avg_proxy_reward": 0.0,
            "samples": 0,
        }

    return {
        "accuracy": correct / float(total),
        "avg_proxy_reward": reward_sum / float(total),
        "samples": float(total),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train offline RL agent from JSONL transitions.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "fake_transitions.jsonl",
        help="Path to JSONL transitions dataset.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "artifacts" / "rl_agent_torch_linear.json",
        help="Output model path.",
    )
    parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="cql",
        help="Offline RL algorithm. cql is the default; q_learning is kept as a baseline.",
    )
    parser.add_argument("--epochs", type=int, default=40, help="Training epochs.")
    parser.add_argument("--gamma", type=float, default=0.96, help="Discount factor.")
    parser.add_argument("--learning-rate", type=float, default=0.003, help="Learning rate.")
    parser.add_argument("--l2", type=float, default=0.0005, help="L2 weight decay.")
    parser.add_argument("--cql-alpha", type=float, default=0.50, help="CQL conservative penalty weight.")
    parser.add_argument("--cql-temperature", type=float, default=1.0, help="CQL logsumexp temperature.")
    parser.add_argument(
        "--behavior-cloning-weight",
        type=float,
        default=0.50,
        help=(
            "Auxiliary supervised loss on dataset actions. "
            "This keeps very small offline smoke-trains usable while the main objective remains CQL/Q-learning."
        ),
    )
    parser.add_argument("--target-update-period", type=int, default=1, help="Epochs between target-network syncs.")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size for training.")
    parser.add_argument("--val-ratio", type=float, default=0.2, help="Validation split ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--device", type=str, default="cpu", help="Torch device (default: cpu).")
    parser.add_argument(
        "--init-policy",
        choices=("web_prior", "random"),
        default="web_prior",
        help=(
            "Initial policy. web_prior seeds HTTP subtype weights from the state schema so short smoke-trains "
            "remain usable; random trains from scratch."
        ),
    )
    parser.add_argument("--log-every", type=int, default=5, help="Epoch logging interval.")
    return parser.parse_args()


def build_model(seed: int, device: torch.device, init_policy: str) -> nn.Linear:
    torch.manual_seed(seed)
    model = nn.Linear(STATE_DIM, len(ACTIONS)).to(device)
    if init_policy == "web_prior":
        with torch.no_grad():
            model.weight.zero_()
            model.bias.fill_(-1.0)
            model.bias[ACTION_KEEP_NORMAL] = 0.25
            model.bias[ACTION_ROUTE_SQLI] = 0.0
            model.bias[ACTION_ROUTE_CMDI] = 0.0
            model.bias[ACTION_ROUTE_SSTI] = 0.0
            model.bias[ACTION_ROUTE_SSRF] = 0.0
            model.weight[ACTION_ROUTE_SQLI, 7] = 5.0
            model.weight[ACTION_ROUTE_CMDI, 8] = 5.0
            model.weight[ACTION_ROUTE_SSTI, 9] = 5.0
            model.weight[ACTION_ROUTE_SSRF, 10] = 5.0
    return model


def export_model_json(model: nn.Linear, output_path: Path, metadata: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with torch.no_grad():
        payload = {
            "state_schema": STATE_SCHEMA_VERSION,
            "state_dim": STATE_DIM,
            "actions": ACTIONS,
            "weights": model.weight.detach().cpu().tolist(),
            "bias": model.bias.detach().cpu().tolist(),
            "metadata": {
                "trained_with": "pytorch",
                "model": f"nn.Linear({STATE_DIM}, {len(ACTIONS)})",
                **metadata,
            },
        }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main() -> None:
    args = parse_args()

    if args.epochs <= 0:
        raise ValueError("--epochs must be > 0")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")
    if args.cql_alpha < 0.0:
        raise ValueError("--cql-alpha must be >= 0")
    if args.cql_temperature <= 0.0:
        raise ValueError("--cql-temperature must be > 0")
    if args.behavior_cloning_weight < 0.0:
        raise ValueError("--behavior-cloning-weight must be >= 0")
    if args.target_update_period <= 0:
        raise ValueError("--target-update-period must be > 0")
    if not (0.0 < args.val_ratio < 0.9):
        raise ValueError("--val-ratio must be between 0 and 0.9")

    if args.device != "cpu" and not torch.cuda.is_available():
        raise RuntimeError("CUDA device requested but not available. Use --device cpu.")
    device = torch.device(args.device)

    random.seed(args.seed)
    torch.manual_seed(args.seed)

    transitions = load_transitions(args.dataset)
    if not transitions:
        raise RuntimeError(f"No transitions loaded from: {args.dataset}")

    train_set, val_set = split_dataset(transitions, args.val_ratio, args.seed)

    model = build_model(args.seed, device, args.init_policy)
    target_model = build_model(args.seed, device, args.init_policy)
    target_model.load_state_dict(model.state_dict())
    target_model.eval()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.l2)

    train_tensors = to_tensors(train_set, device)

    print("Offline training started")
    print(f"- Dataset: {args.dataset}")
    print(f"- Device: {device}")
    print(f"- Algorithm: {args.algorithm}")
    print(f"- Init policy: {args.init_policy}")
    print(f"- Total transitions: {len(transitions)}")
    print(f"- Train transitions: {len(train_set)}")
    print(f"- Validation transitions: {len(val_set)}")

    for epoch in range(1, args.epochs + 1):
        model.train()
        indices = list(range(len(train_set)))
        random.Random(args.seed + epoch).shuffle(indices)

        epoch_loss_sum = 0.0
        epoch_td_sum = 0.0
        epoch_cql_sum = 0.0
        epoch_bc_sum = 0.0
        epoch_samples = 0

        for offset in range(0, len(indices), args.batch_size):
            batch_indices = indices[offset : offset + args.batch_size]
            batch = torch.tensor(batch_indices, dtype=torch.int64, device=device)

            states = train_tensors["states"].index_select(0, batch)
            actions = train_tensors["actions"].index_select(0, batch)
            rewards = train_tensors["rewards"].index_select(0, batch)
            next_states = train_tensors["next_states"].index_select(0, batch)
            dones = train_tensors["dones"].index_select(0, batch)
            current_mask = train_tensors["current_mask"].index_select(0, batch)
            next_mask = train_tensors["next_mask"].index_select(0, batch)

            q_values = model(states)
            q_selected = q_values.gather(1, actions.unsqueeze(1)).squeeze(1)

            with torch.no_grad():
                q_next = target_model(next_states)
                q_next = q_next.masked_fill(~next_mask, -1e9)
                max_next = q_next.max(dim=1).values
                targets = rewards + (1.0 - dones) * args.gamma * max_next

            td_loss = F.mse_loss(q_selected, targets)
            cql_loss = torch.zeros((), dtype=torch.float32, device=device)
            if args.algorithm == "cql":
                cql_loss = conservative_q_regularizer(
                    q_values=q_values,
                    actions=actions,
                    current_mask=current_mask,
                    temperature=args.cql_temperature,
                )

            masked_logits = q_values.masked_fill(~current_mask, -1e9)
            bc_loss = F.cross_entropy(masked_logits, actions)

            loss = td_loss + args.cql_alpha * cql_loss + args.behavior_cloning_weight * bc_loss

            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=10.0)
            optimizer.step()

            batch_size = len(batch_indices)
            epoch_loss_sum += float(loss.item()) * batch_size
            epoch_td_sum += float(td_loss.item()) * batch_size
            epoch_cql_sum += float(cql_loss.item()) * batch_size
            epoch_bc_sum += float(bc_loss.item()) * batch_size
            epoch_samples += batch_size

        mse = epoch_loss_sum / float(max(1, epoch_samples))
        td_mse = epoch_td_sum / float(max(1, epoch_samples))
        cql_penalty = epoch_cql_sum / float(max(1, epoch_samples))
        bc_penalty = epoch_bc_sum / float(max(1, epoch_samples))

        if epoch % args.target_update_period == 0:
            target_model.load_state_dict(model.state_dict())

        should_log = epoch == 1 or epoch == args.epochs or (epoch % args.log_every == 0)
        if should_log:
            train_metrics = evaluate(model, train_set, device)
            val_metrics = evaluate(model, val_set, device)
            print(
                "Epoch"
                f" {epoch:03d}"
                f" | loss={mse:.5f}"
                f" | td_mse={td_mse:.5f}"
                f" | cql={cql_penalty:.5f}"
                f" | bc={bc_penalty:.5f}"
                f" | train_acc={train_metrics['accuracy']:.3f}"
                f" | val_acc={val_metrics['accuracy']:.3f}"
                f" | val_proxy_reward={val_metrics['avg_proxy_reward']:.3f}"
            )

    training_metadata = {
        "algorithm": args.algorithm,
        "gamma": args.gamma,
        "cql_alpha": args.cql_alpha if args.algorithm == "cql" else 0.0,
        "cql_temperature": args.cql_temperature,
        "behavior_cloning_weight": args.behavior_cloning_weight,
        "init_policy": args.init_policy,
        "target_update_period": args.target_update_period,
        "dataset": str(args.dataset),
    }
    export_model_json(model, args.output, training_metadata)

    final_train = evaluate(model, train_set, device)
    final_val = evaluate(model, val_set, device)

    metrics_path = args.output.with_suffix(".metrics.json")
    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset": str(args.dataset),
                "model": str(args.output),
                "algorithm": args.algorithm,
                "epochs": args.epochs,
                "gamma": args.gamma,
                "learning_rate": args.learning_rate,
                "l2": args.l2,
                "cql_alpha": args.cql_alpha if args.algorithm == "cql" else 0.0,
                "cql_temperature": args.cql_temperature,
                "behavior_cloning_weight": args.behavior_cloning_weight,
                "init_policy": args.init_policy,
                "target_update_period": args.target_update_period,
                "batch_size": args.batch_size,
                "device": str(device),
                "train_metrics": final_train,
                "validation_metrics": final_val,
            },
            f,
            indent=2,
        )

    print("Training finished")
    print(f"- Model saved: {args.output}")
    print(f"- Metrics saved: {metrics_path}")
    print(f"- Final train accuracy: {final_train['accuracy']:.3f}")
    print(f"- Final validation accuracy: {final_val['accuracy']:.3f}")

    sample = random.choice(val_set if val_set else train_set)
    model.eval()
    with torch.no_grad():
        sample_tensor = torch.tensor(sample.state, dtype=torch.float32, device=device).unsqueeze(0)
        sample_q = model(sample_tensor).squeeze(0)
        sample_mask = torch.zeros(len(ACTIONS), dtype=torch.bool, device=device)
        for idx in allowed_action_indices(sample.protocol):
            sample_mask[idx] = True
        sample_q = sample_q.masked_fill(~sample_mask, -1e9)
        action_idx = int(sample_q.argmax().item())

    print("Sample decision")
    print(f"- Protocol: {sample.protocol}")
    print(f"- Predicted action: {action_name(action_idx)} ({action_idx})")
    print(f"- Optimal action: {action_name(sample.optimal_action or 0)} ({sample.optimal_action})")


if __name__ == "__main__":
    main()
