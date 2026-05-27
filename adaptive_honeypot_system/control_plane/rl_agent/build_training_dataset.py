from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc


def origin_id(row: dict[str, Any]) -> str:
    if row.get("decision_id"):
        return str(row["decision_id"])
    session_id = str(row.get("session_id") or "unknown-session")
    step = str(row.get("step") if row.get("step") is not None else "unknown-step")
    return f"{session_id}:{step}"


def annotate(row: dict[str, Any], *, source: str, repeat_index: int | None = None) -> dict[str, Any]:
    item = dict(row)
    item["source"] = source
    item.setdefault("sample_origin_id", origin_id(item))
    if repeat_index is not None:
        item["source_repeat_index"] = repeat_index
    return item


def first_present(row: dict[str, Any], *keys: str, default: str = "unknown") -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return str(value)
    return default


def update_summary(summary: dict[str, Any], row: dict[str, Any]) -> None:
    source = str(row.get("source") or "unknown")
    session_id = str(row.get("session_id") or "")
    action = first_present(row, "action_name", "action")
    optimal = first_present(row, "optimal_action_name", "optimal_action")
    attack_type = first_present(row, "attack_type")

    summary["transitions"] += 1
    summary["source_counts"][source] += 1
    summary["action_counts"][action] += 1
    summary["optimal_action_counts"][optimal] += 1
    summary["attack_type_counts"][attack_type] += 1
    if session_id:
        summary["sessions_by_source"][source].add(session_id)
    else:
        summary["missing_session_transitions"] += 1


def serializable_summary(summary: dict[str, Any]) -> dict[str, Any]:
    sessions_by_source = summary.pop("sessions_by_source")
    return {
        **summary,
        "source_counts": dict(sorted(summary["source_counts"].items())),
        "action_counts": dict(sorted(summary["action_counts"].items())),
        "optimal_action_counts": dict(sorted(summary["optimal_action_counts"].items())),
        "attack_type_counts": dict(sorted(summary["attack_type_counts"].items())),
        "source_session_counts": {
            source: len(session_ids) for source, session_ids in sorted(sessions_by_source.items())
        },
    }


def build_dataset(
    *,
    synthetic_path: Path,
    replay_path: Path,
    output_path: Path,
    replay_repeat: int,
    summary_path: Path,
) -> dict[str, Any]:
    if replay_repeat < 0:
        raise ValueError("--replay-repeat must be >= 0")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "transitions": 0,
        "missing_session_transitions": 0,
        "source_counts": Counter(),
        "action_counts": Counter(),
        "optimal_action_counts": Counter(),
        "attack_type_counts": Counter(),
        "sessions_by_source": defaultdict(set),
        "inputs": {
            "synthetic": str(synthetic_path),
            "replay": str(replay_path),
            "replay_repeat": replay_repeat,
        },
    }

    with output_path.open("w", encoding="utf-8") as output:
        for row in read_jsonl(synthetic_path):
            item = annotate(row, source="synthetic")
            update_summary(summary, item)
            output.write(json.dumps(item, ensure_ascii=True) + "\n")

        replay_rows = list(read_jsonl(replay_path)) if replay_path.exists() else []
        for repeat_index in range(replay_repeat):
            for row in replay_rows:
                item = annotate(row, source="replay", repeat_index=repeat_index)
                update_summary(summary, item)
                output.write(json.dumps(item, ensure_ascii=True) + "\n")

    final_summary = serializable_summary(summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(final_summary, f, indent=2)
    return final_summary


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build an annotated offline RL training dataset.")
    parser.add_argument(
        "--synthetic",
        type=Path,
        default=root / "data" / "fake_transitions.jsonl",
        help="Synthetic transition JSONL path.",
    )
    parser.add_argument(
        "--replay",
        type=Path,
        default=root / "data" / "replay_buffer.jsonl",
        help="Replay buffer JSONL path.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "mixed_train_transitions.jsonl",
        help="Output JSONL path.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Output summary JSON path. Defaults to <output>.summary.json.",
    )
    parser.add_argument(
        "--replay-repeat",
        type=int,
        default=1,
        help="How many times to append replay transitions after synthetic rows.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary_path = args.summary or args.output.with_suffix(".summary.json")
    summary = build_dataset(
        synthetic_path=args.synthetic,
        replay_path=args.replay,
        output_path=args.output,
        replay_repeat=args.replay_repeat,
        summary_path=summary_path,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
