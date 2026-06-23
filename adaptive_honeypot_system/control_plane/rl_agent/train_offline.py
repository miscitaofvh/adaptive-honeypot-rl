from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import random
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

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
    strategy: str = "grouped",
    group_by: str = "session_id",
) -> Tuple[List[Transition], List[Transition], Dict[str, Any]]:
    rng = random.Random(seed)
    if strategy == "transition":
        indices = list(range(len(transitions)))
        rng.shuffle(indices)
        split_at = int((1.0 - validation_ratio) * len(indices))
        train_idx = indices[:split_at]
        val_idx = indices[split_at:]
    elif strategy == "grouped":
        session_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, transition in enumerate(transitions):
            group_key = transition.session_id or f"missing-session-{idx}"
            session_groups[group_key].append(idx)

        stratified_groups: Dict[str, Dict[str, List[int]]] = defaultdict(dict)
        for group_key, group_indices in session_groups.items():
            group_transitions = [transitions[idx] for idx in group_indices]
            source = Counter(transition.source or "unknown" for transition in group_transitions).most_common(1)[0][0]
            attack_type = Counter(
                transition.attack_type or "unknown" for transition in group_transitions
            ).most_common(1)[0][0]
            stratum = f"{source}:{attack_type}"
            stratified_groups[stratum][group_key] = group_indices

        train_idx = []
        val_idx = []
        for stratum in sorted(stratified_groups):
            groups = stratified_groups[stratum]
            group_keys = list(groups)
            rng.shuffle(group_keys)

            if len(group_keys) <= 1:
                val_group_count = 0
            else:
                requested = int(round(len(group_keys) * validation_ratio))
                val_group_count = min(len(group_keys) - 1, max(1, requested))

            val_keys = set(group_keys[:val_group_count])
            for key in group_keys:
                if key in val_keys:
                    val_idx.extend(groups[key])
                else:
                    train_idx.extend(groups[key])
    else:
        raise ValueError(f"Unsupported split strategy: {strategy}")

    train_set = [transitions[i] for i in train_idx]
    val_set = [transitions[i] for i in val_idx]
    summary = build_split_summary(
        train_set=train_set,
        val_set=val_set,
        validation_ratio=validation_ratio,
        strategy=strategy,
        group_by=group_by,
    )
    return train_set, val_set, summary


def named_action_counts(values: Iterable[int]) -> Dict[str, int]:
    counts = Counter(int(value) for value in values if value is not None)
    return {action_name(idx): counts.get(idx, 0) for idx in range(len(ACTIONS))}


def summarize_dataset(transitions: Sequence[Transition]) -> Dict[str, Any]:
    sessions = {transition.session_id for transition in transitions if transition.session_id}
    sessions_by_source: Dict[str, set[str]] = defaultdict(set)
    for transition in transitions:
        if transition.session_id:
            sessions_by_source[transition.source or "unknown"].add(transition.session_id)

    return {
        "transitions": len(transitions),
        "sessions": len(sessions),
        "missing_session_transitions": sum(1 for transition in transitions if not transition.session_id),
        "source_counts": dict(sorted(Counter(transition.source or "unknown" for transition in transitions).items())),
        "source_session_counts": {source: len(session_ids) for source, session_ids in sorted(sessions_by_source.items())},
        "attack_type_counts": dict(sorted(Counter(transition.attack_type or "unknown" for transition in transitions).items())),
        "stratum_counts": dict(sorted(
            Counter(
                f"{transition.source or 'unknown'}:{transition.attack_type or 'unknown'}"
                for transition in transitions
            ).items()
        )),
        "action_counts": named_action_counts(transition.action for transition in transitions),
        "optimal_action_counts": named_action_counts(
            transition.optimal_action for transition in transitions if transition.optimal_action is not None
        ),
    }


def transition_fingerprint(transition: Transition) -> str:
    payload = {
        "state": transition.state,
        "action": transition.action,
        "reward": round(float(transition.reward), 6),
        "next_state": transition.next_state,
        "done": transition.done,
        "optimal_action": transition.optimal_action,
        "protocol": transition.protocol,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def fingerprint_stats(transitions: Sequence[Transition]) -> Dict[str, int]:
    counts = Counter(transition_fingerprint(transition) for transition in transitions)
    duplicate_rows = sum(count - 1 for count in counts.values() if count > 1)
    return {
        "rows": len(transitions),
        "unique_fingerprints": len(counts),
        "duplicate_rows": duplicate_rows,
        "max_duplicate_count": max(counts.values()) if counts else 0,
    }


def build_split_summary(
    *,
    train_set: Sequence[Transition],
    val_set: Sequence[Transition],
    validation_ratio: float,
    strategy: str,
    group_by: str,
) -> Dict[str, Any]:
    train_sessions = {transition.session_id for transition in train_set if transition.session_id}
    val_sessions = {transition.session_id for transition in val_set if transition.session_id}
    session_overlap = sorted(train_sessions & val_sessions)

    train_fingerprints = {transition_fingerprint(transition) for transition in train_set}
    val_fingerprints = {transition_fingerprint(transition) for transition in val_set}
    fingerprint_overlap = train_fingerprints & val_fingerprints

    return {
        "strategy": strategy,
        "group_by": group_by,
        "validation_ratio": validation_ratio,
        "train": summarize_dataset(train_set),
        "validation": summarize_dataset(val_set),
        "train_fingerprint_stats": fingerprint_stats(train_set),
        "validation_fingerprint_stats": fingerprint_stats(val_set),
        "session_overlap_count": len(session_overlap),
        "session_overlap_sample": session_overlap[:10],
        "transition_fingerprint_overlap_count": len(fingerprint_overlap),
        "transition_fingerprint_overlap_rate": (
            len(fingerprint_overlap) / float(max(1, min(len(train_fingerprints), len(val_fingerprints))))
        ),
        "transition_fingerprint_overlap_sample": sorted(fingerprint_overlap)[:10],
    }


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


def summarize_prediction_records(
    records: Sequence[Tuple[int, int, float]],
    *,
    include_confusion: bool = True,
) -> Dict[str, Any]:
    if not records:
        return {
            "accuracy": 0.0,
            "avg_proxy_reward": 0.0,
            "samples": 0,
            "macro_f1": 0.0,
            "weighted_f1": 0.0,
            "balanced_accuracy": 0.0,
        }

    total = len(records)
    correct = sum(1 for actual, predicted, _ in records if actual == predicted)
    reward_sum = sum(reward for _, _, reward in records)

    confusion = [[0 for _ in ACTIONS] for _ in ACTIONS]
    for actual, predicted, _ in records:
        if 0 <= actual < len(ACTIONS) and 0 <= predicted < len(ACTIONS):
            confusion[actual][predicted] += 1

    per_action: Dict[str, Dict[str, float]] = {}
    f1_values = []
    weighted_f1_sum = 0.0
    recall_values = []
    for idx in range(len(ACTIONS)):
        true_positive = confusion[idx][idx]
        support = sum(confusion[idx])
        predicted_count = sum(confusion[row][idx] for row in range(len(ACTIONS)))
        precision = true_positive / predicted_count if predicted_count else 0.0
        recall = true_positive / support if support else 0.0
        f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        if support:
            f1_values.append(f1)
            recall_values.append(recall)
            weighted_f1_sum += f1 * support

        per_action[action_name(idx)] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
            "predicted": predicted_count,
        }

    result: Dict[str, Any] = {
        "accuracy": correct / float(total),
        "avg_proxy_reward": reward_sum / float(total),
        "samples": total,
        "macro_f1": sum(f1_values) / float(len(f1_values)) if f1_values else 0.0,
        "weighted_f1": weighted_f1_sum / float(total),
        "balanced_accuracy": sum(recall_values) / float(len(recall_values)) if recall_values else 0.0,
        "actual_action_counts": {
            action_name(idx): sum(confusion[idx]) for idx in range(len(ACTIONS))
        },
        "predicted_action_counts": {
            action_name(idx): sum(confusion[row][idx] for row in range(len(ACTIONS))) for idx in range(len(ACTIONS))
        },
        "per_action": per_action,
    }
    if include_confusion:
        result["confusion_matrix"] = {
            action_name(row): {
                action_name(col): confusion[row][col] for col in range(len(ACTIONS))
            }
            for row in range(len(ACTIONS))
        }
    return result


def evaluate(model: nn.Module, transitions: Sequence[Transition], device: torch.device) -> Dict[str, Any]:
    if not transitions:
        result = summarize_prediction_records([])
        result["by_source"] = {}
        result["by_attack_type"] = {}
        return result

    with torch.no_grad():
        tensors = to_tensors(transitions, device)
        q_values = model(tensors["states"])
        masked_q = q_values.masked_fill(~tensors["current_mask"], -1e9)
        predicted = masked_q.argmax(dim=1).detach().cpu().tolist()

    records: List[Tuple[int, int, float]] = []
    records_by_source: Dict[str, List[Tuple[int, int, float]]] = defaultdict(list)
    records_by_attack_type: Dict[str, List[Tuple[int, int, float]]] = defaultdict(list)

    for idx, transition in enumerate(transitions):
        if transition.optimal_action is None:
            continue
        pred_action = int(predicted[idx])
        optimal_action = int(transition.optimal_action)
        record = (optimal_action, pred_action, proxy_reward(pred_action, optimal_action))
        records.append(record)
        records_by_source[transition.source or "unknown"].append(record)
        records_by_attack_type[transition.attack_type or "unknown"].append(record)

    result = summarize_prediction_records(records)
    result["by_source"] = {
        source: summarize_prediction_records(group_records, include_confusion=False)
        for source, group_records in sorted(records_by_source.items())
    }
    result["by_attack_type"] = {
        attack_type: summarize_prediction_records(group_records, include_confusion=False)
        for attack_type, group_records in sorted(records_by_attack_type.items())
    }
    return result


def compact_metrics(metrics: Dict[str, Any]) -> Dict[str, float | int]:
    return {
        "accuracy": float(metrics["accuracy"]),
        "macro_f1": float(metrics["macro_f1"]),
        "weighted_f1": float(metrics["weighted_f1"]),
        "balanced_accuracy": float(metrics["balanced_accuracy"]),
        "avg_proxy_reward": float(metrics["avg_proxy_reward"]),
        "samples": int(metrics["samples"]),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train offline RL agent from JSONL transitions.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "training_dataset.jsonl",
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
    parser.add_argument(
        "--split-strategy",
        choices=("grouped", "transition"),
        default="grouped",
        help=(
            "Validation split strategy. grouped keeps whole sessions in either train or validation "
            "and stratifies by source plus dominant attack type; transition is the older random transition split."
        ),
    )
    parser.add_argument(
        "--group-by",
        choices=("session_id",),
        default="session_id",
        help="Grouping key for grouped validation split.",
    )
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

    train_set, val_set, split_summary = split_dataset(
        transitions,
        args.val_ratio,
        args.seed,
        strategy=args.split_strategy,
        group_by=args.group_by,
    )
    if not train_set:
        raise RuntimeError("Training split is empty; lower --val-ratio or provide more sessions.")
    if not val_set:
        raise RuntimeError("Validation split is empty; provide more sessions or use --split-strategy transition.")
    if args.split_strategy == "grouped" and split_summary["session_overlap_count"]:
        raise RuntimeError(
            "Strict validation failed: session IDs exist in both train and validation. "
            f"Examples: {split_summary['session_overlap_sample']}"
        )
    if args.split_strategy != "grouped" and split_summary["session_overlap_count"]:
        print(
            "WARNING: validation contains session overlap because --split-strategy transition was used. "
            "Use --split-strategy grouped for report-grade validation."
        )

    model = build_model(args.seed, device, args.init_policy)
    target_model = build_model(args.seed, device, args.init_policy)
    target_model.load_state_dict(model.state_dict())
    target_model.eval()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.l2)

    train_tensors = to_tensors(train_set, device)
    initial_train = evaluate(model, train_set, device)
    initial_val = evaluate(model, val_set, device)
    epoch_history: List[Dict[str, Any]] = []

    print("Offline training started")
    print(f"- Dataset: {args.dataset}")
    print(f"- Device: {device}")
    print(f"- Algorithm: {args.algorithm}")
    print(f"- Init policy: {args.init_policy}")
    print(f"- Split strategy: {args.split_strategy} by {args.group_by}")
    print(f"- Total transitions: {len(transitions)}")
    print(f"- Train transitions: {len(train_set)}")
    print(f"- Validation transitions: {len(val_set)}")
    print(f"- Train sessions: {split_summary['train']['sessions']}")
    print(f"- Validation sessions: {split_summary['validation']['sessions']}")
    print(f"- Session overlap: {split_summary['session_overlap_count']}")
    print(f"- Transition fingerprint overlap: {split_summary['transition_fingerprint_overlap_count']}")
    print(f"- Initial train accuracy: {initial_train['accuracy']:.3f}")
    print(f"- Initial validation accuracy: {initial_val['accuracy']:.3f}")

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
            epoch_history.append({
                "epoch": epoch,
                "loss": mse,
                "td_mse": td_mse,
                "cql_penalty": cql_penalty,
                "behavior_cloning_loss": bc_penalty,
                "train": compact_metrics(train_metrics),
                "validation": compact_metrics(val_metrics),
            })
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
                "split_strategy": args.split_strategy,
                "group_by": args.group_by,
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
                "split_strategy": args.split_strategy,
                "group_by": args.group_by,
                "device": str(device),
                "dataset_summary": summarize_dataset(transitions),
                "split_summary": split_summary,
                "initial_train_metrics": initial_train,
                "initial_validation_metrics": initial_val,
                "epoch_history": epoch_history,
                "train_metrics": final_train,
                "validation_metrics": final_val,
                "generalization": {
                    "accuracy_gap_train_minus_validation": final_train["accuracy"] - final_val["accuracy"],
                    "macro_f1_gap_train_minus_validation": final_train["macro_f1"] - final_val["macro_f1"],
                    "weighted_f1_gap_train_minus_validation": final_train["weighted_f1"] - final_val["weighted_f1"],
                    "overfit_warning_accuracy_gap_gt_0_05": (
                        final_train["accuracy"] - final_val["accuracy"] > 0.05
                    ),
                    "overfit_warning_macro_f1_gap_gt_0_05": (
                        final_train["macro_f1"] - final_val["macro_f1"] > 0.05
                    ),
                },
            },
            f,
            indent=2,
        )

    print("Training finished")
    print(f"- Model saved: {args.output}")
    print(f"- Metrics saved: {metrics_path}")
    print(f"- Final train accuracy: {final_train['accuracy']:.3f}")
    print(f"- Final validation accuracy: {final_val['accuracy']:.3f}")
    print(f"- Final validation macro F1: {final_val['macro_f1']:.3f}")
    print(f"- Generalization accuracy gap: {final_train['accuracy'] - final_val['accuracy']:.3f}")

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
