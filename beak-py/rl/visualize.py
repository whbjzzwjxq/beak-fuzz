"""Visualization suite for RL vs Bandit comparison.

Generates publication-quality figures showing RL learning dynamics
and performance comparisons against baseline policies.

Usage:
    python -m beak_py.rl.visualize --metrics-dir output/ --output-dir paper/figures/
    python -m beak_py.rl.visualize --metrics-dir output/ --paper-mode
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np


def load_metrics(metrics_dir: Path) -> dict[str, list[dict]]:
    """Load metrics JSONL files grouped by policy type."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in sorted(metrics_dir.glob("*-metrics.jsonl")):
        records = []
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if records:
            policy_type = records[0].get("policy_type", "unknown")
            groups[policy_type].append(records)
    return groups


def _setup_style(paper_mode: bool):
    if paper_mode:
        matplotlib.rcParams.update({
            "font.family": "serif",
            "font.size": 10,
            "axes.labelsize": 11,
            "axes.titlesize": 12,
            "legend.fontsize": 9,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "figure.dpi": 300,
            "savefig.dpi": 300,
            "savefig.bbox": "tight",
        })
    else:
        plt.style.use("seaborn-v0_8-whitegrid")


def _extract_series(runs: list[list[dict]], key: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Extract mean and std across multiple runs for a given key."""
    max_len = max(len(r) for r in runs) if runs else 0
    if max_len == 0:
        return np.array([]), np.array([]), np.array([])

    matrix = np.full((len(runs), max_len), np.nan)
    for i, run in enumerate(runs):
        for j, rec in enumerate(run):
            matrix[i, j] = rec.get(key, 0)

    iterations = np.array([run[j].get("iteration", j) for j, _ in enumerate(runs[0])])
    mean = np.nanmean(matrix, axis=0)
    std = np.nanstd(matrix, axis=0)
    return iterations, mean, std


POLICY_COLORS = {
    "random": "#95a5a6",
    "bandit": "#e74c3c",
    "linucb": "#3498db",
    "external": "#2ecc71",
    "rl": "#2ecc71",
}
POLICY_LABELS = {
    "random": "Random (Uniform)",
    "bandit": "UCB1 Bandit",
    "linucb": "LinUCB (RL)",
    "external": "PPO (Deep RL)",
    "rl": "PPO (Deep RL)",
}


def plot_cumulative_reward(groups: dict, output_dir: Path, ext: str):
    """Fig 1: Cumulative reward learning curves."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for policy, runs in groups.items():
        iters, mean, std = _extract_series(runs, "cumulative_reward")
        if len(iters) == 0:
            continue
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, mean, color=color, label=label, linewidth=1.5)
        ax.fill_between(iters, mean - std, mean + std, alpha=0.15, color=color)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Cumulative Reward")
    ax.set_title("Learning Curve: Cumulative Reward")
    ax.legend()
    fig.savefig(output_dir / f"fig1_cumulative_reward.{ext}")
    plt.close(fig)


def plot_bucket_coverage(groups: dict, output_dir: Path, ext: str):
    """Fig 2: Unique bucket ID coverage over iterations."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for policy, runs in groups.items():
        iters, mean, std = _extract_series(runs, "unique_bucket_ids")
        if len(iters) == 0:
            continue
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, mean, color=color, label=label, linewidth=1.5)
        ax.fill_between(iters, mean - std, mean + std, alpha=0.15, color=color)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Unique Bucket IDs")
    ax.set_title("Bucket Coverage Growth")
    ax.legend()
    fig.savefig(output_dir / f"fig2_bucket_coverage.{ext}")
    plt.close(fig)


def plot_bug_discovery(groups: dict, output_dir: Path, ext: str):
    """Fig 3: Cumulative bug count over iterations."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for policy, runs in groups.items():
        iters, mean, std = _extract_series(runs, "bug_count")
        if len(iters) == 0:
            continue
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, mean, color=color, label=label, linewidth=1.5)
        ax.fill_between(iters, mean - std, mean + std, alpha=0.15, color=color)
        # Annotate first bug.
        for j in range(len(mean)):
            if mean[j] > 0:
                ax.annotate(
                    f"first bug @ {int(iters[j])}",
                    xy=(iters[j], mean[j]),
                    fontsize=8,
                    color=color,
                )
                break
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Cumulative Bugs Found")
    ax.set_title("Bug Discovery Speed")
    ax.legend()
    fig.savefig(output_dir / f"fig3_bug_discovery.{ext}")
    plt.close(fig)


def plot_arm_heatmap(groups: dict, output_dir: Path, ext: str):
    """Fig 4: Arm selection distribution heatmap."""
    arm_names = [
        "splice", "reg_mut", "const_mut", "insert",
        "delete", "duplicate", "swap", "mnemonic",
    ]
    for policy, runs in groups.items():
        if not runs or not runs[0]:
            continue
        run = runs[0]  # Use first run for heatmap.

        window = max(1, len(run) // 10)
        n_windows = len(run) // window
        if n_windows == 0:
            continue

        heatmap = np.zeros((8, n_windows))
        for w in range(n_windows):
            segment = run[w * window : (w + 1) * window]
            for rec in segment:
                pulls = rec.get("arm_pulls", [0] * 8)
                for arm_idx, count in enumerate(pulls[:8]):
                    heatmap[arm_idx, w] += count
            col_sum = heatmap[:, w].sum()
            if col_sum > 0:
                heatmap[:, w] /= col_sum

        fig, ax = plt.subplots(figsize=(10, 4))
        im = ax.imshow(heatmap, aspect="auto", cmap="YlOrRd", interpolation="nearest")
        ax.set_yticks(range(8))
        ax.set_yticklabels(arm_names)
        ax.set_xlabel(f"Window ({window} iters each)")
        ax.set_ylabel("Mutator Arm")
        label = POLICY_LABELS.get(policy, policy)
        ax.set_title(f"Arm Selection Distribution - {label}")
        plt.colorbar(im, ax=ax, label="Selection Frequency")
        fig.savefig(output_dir / f"fig4_arm_heatmap_{policy}.{ext}")
        plt.close(fig)


def plot_arm_comparison(groups: dict, output_dir: Path, ext: str):
    """Fig 5: Side-by-side arm selection comparison (bar chart)."""
    arm_names = [
        "splice", "reg_mut", "const_mut", "insert",
        "delete", "duplicate", "swap", "mnemonic",
    ]
    policies_with_data = []
    for policy, runs in groups.items():
        if runs and runs[0]:
            last_rec = runs[0][-1]
            pulls = last_rec.get("arm_pulls", [0] * 8)
            if sum(pulls[:8]) > 0:
                policies_with_data.append((policy, pulls[:8]))
    if len(policies_with_data) < 2:
        return

    n_policies = len(policies_with_data)
    x = np.arange(8)
    width = 0.8 / n_policies

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, (policy, pulls) in enumerate(policies_with_data):
        total = sum(pulls)
        fracs = [p / total if total > 0 else 0 for p in pulls]
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.bar(x + i * width - 0.4 + width / 2, fracs, width,
               color=color, label=label, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(arm_names, rotation=30, ha="right")
    ax.set_ylabel("Selection Fraction")
    ax.set_title("Mutator Arm Selection Distribution (Final)")
    ax.legend()
    ax.set_ylim(0, 1.0)
    fig.tight_layout()
    fig.savefig(output_dir / f"fig5_arm_comparison.{ext}")
    plt.close(fig)


def plot_entropy(output_dir: Path, log_dir: Path, ext: str):
    """Fig 5: Policy entropy decay curve (from RL server logs)."""
    log_file = log_dir / "rl_server_metrics.jsonl"
    if not log_file.exists():
        return

    records = []
    for line in log_file.read_text().splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not records:
        return

    steps = [r["mutator_step"] for r in records]
    entropies = [r.get("entropy", 0) for r in records]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(steps, entropies, color="#2ecc71", linewidth=1.5)
    ax.set_xlabel("Training Step")
    ax.set_ylabel("Policy Entropy (nats)")
    ax.set_title("Policy Entropy Decay")
    ax.axhline(y=np.log(8), color="#999", linestyle="--", linewidth=0.8, label="Max entropy (uniform)")
    ax.legend()
    fig.savefig(output_dir / f"fig5_entropy.{ext}")
    plt.close(fig)


def plot_signatures_over_time(groups: dict, output_dir: Path, ext: str):
    """Fig 6: Unique signatures over time."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for policy, runs in groups.items():
        iters, mean, std = _extract_series(runs, "unique_signatures")
        if len(iters) == 0:
            continue
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, mean, color=color, label=label, linewidth=1.5)
        ax.fill_between(iters, mean - std, mean + std, alpha=0.15, color=color)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Unique Signatures")
    ax.set_title("Corpus Diversity Growth")
    ax.legend()
    fig.savefig(output_dir / f"fig6_signatures.{ext}")
    plt.close(fig)


def plot_reward_rate(groups: dict, output_dir: Path, ext: str):
    """Fig 7: Windowed reward rate (recent_reward_100)."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for policy, runs in groups.items():
        iters, mean, std = _extract_series(runs, "recent_reward_100")
        if len(iters) == 0:
            continue
        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, mean, color=color, label=label, linewidth=1.5, alpha=0.9)
        ax.fill_between(iters, mean - std, mean + std, alpha=0.1, color=color)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Recent Reward Rate (100-iter window)")
    ax.set_title("Reward Rate Over Time")
    ax.legend()
    fig.savefig(output_dir / f"fig7_reward_rate.{ext}")
    plt.close(fig)


def _compute_per_step_reward(records: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    """Derive per-step reward from cumulative reward."""
    iters = np.array([r.get("iteration", i) for i, r in enumerate(records)])
    cum = np.array([r.get("cumulative_reward", 0.0) for r in records])
    per_step = np.diff(cum, prepend=0.0)
    return iters, per_step


def plot_learning_curve(groups: dict, output_dir: Path, ext: str):
    """Fig 8: RL Learning Curve — smoothed per-step reward over training.

    This is the classic RL learning curve: shows how each policy's
    per-step reward evolves, with exponential moving average smoothing.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Left panel: smoothed per-step reward (EMA)
    ax = axes[0]
    ema_alpha = 0.05
    for policy, runs in groups.items():
        if not runs or not runs[0]:
            continue
        run = runs[0]
        iters, per_step = _compute_per_step_reward(run)
        if len(iters) == 0:
            continue

        ema = np.zeros_like(per_step)
        ema[0] = per_step[0]
        for t in range(1, len(per_step)):
            ema[t] = ema_alpha * per_step[t] + (1 - ema_alpha) * ema[t - 1]

        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax.plot(iters, per_step, color=color, alpha=0.15, linewidth=0.5)
        ax.plot(iters, ema, color=color, label=label, linewidth=2)

    ax.set_xlabel("Iteration")
    ax.set_ylabel("Per-Step Reward")
    ax.set_title("Learning Curve (EMA-smoothed)")
    ax.legend()

    # Right panel: cumulative reward normalized by iteration (reward efficiency)
    ax2 = axes[1]
    for policy, runs in groups.items():
        if not runs or not runs[0]:
            continue
        run = runs[0]
        iters = np.array([r.get("iteration", i) for i, r in enumerate(run)])
        cum = np.array([r.get("cumulative_reward", 0.0) for r in run])
        safe_iters = np.where(iters > 0, iters, 1)
        efficiency = cum / safe_iters

        color = POLICY_COLORS.get(policy, "#666")
        label = POLICY_LABELS.get(policy, policy)
        ax2.plot(iters, efficiency, color=color, label=label, linewidth=1.5)

    ax2.set_xlabel("Iteration")
    ax2.set_ylabel("Avg Reward per Iteration")
    ax2.set_title("Reward Efficiency Over Time")
    ax2.legend()

    fig.suptitle("RL Learning Curves", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(output_dir / f"fig8_learning_curve.{ext}")
    plt.close(fig)


def plot_ppo_training(output_dir: Path, log_dir: Path, ext: str):
    """Fig 9: PPO training diagnostics from server logs.

    Plots policy loss, value loss, and entropy over training updates.
    """
    log_file = log_dir / "rl_server_metrics.jsonl"
    if not log_file.exists():
        return

    records = []
    for line in log_file.read_text().splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not records:
        return

    steps = [r["mutator_step"] for r in records]
    entropy = [r.get("entropy", 0) for r in records]
    updates = [r.get("mutator_updates", 0) for r in records]
    req_count = [r.get("request_count", 0) for r in records]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))

    # Top-left: Entropy
    ax = axes[0, 0]
    ax.plot(steps, entropy, color="#2ecc71", linewidth=1.5)
    ax.axhline(y=np.log(8), color="#999", linestyle="--", linewidth=0.8, label="Max (uniform)")
    ax.set_xlabel("Training Step")
    ax.set_ylabel("Policy Entropy (nats)")
    ax.set_title("Policy Entropy Decay")
    ax.legend()

    # Top-right: Updates vs Steps
    ax = axes[0, 1]
    ax.plot(steps, updates, color="#e74c3c", linewidth=1.5)
    ax.set_xlabel("Training Step")
    ax.set_ylabel("Cumulative Policy Updates")
    ax.set_title("Policy Update Frequency")

    # Bottom-left: Request count (throughput)
    ax = axes[1, 0]
    ax.plot(steps, req_count, color="#3498db", linewidth=1.5)
    ax.set_xlabel("Training Step")
    ax.set_ylabel("Cumulative Requests")
    ax.set_title("IPC Request Throughput")

    # Bottom-right: Arm distribution over time (from server perspective)
    ax = axes[1, 1]
    arm_names = ["splice", "reg", "const", "ins", "del", "dup", "swap", "mnem"]
    arm_history = {i: [] for i in range(8)}
    step_list = []
    for r in records:
        dist = r.get("arm_distribution", None)
        if dist and len(dist) >= 8:
            step_list.append(r["mutator_step"])
            for i in range(8):
                arm_history[i].append(dist[i])

    if step_list:
        bottom = np.zeros(len(step_list))
        colors = plt.cm.Set2(np.linspace(0, 1, 8))
        for i in range(8):
            vals = np.array(arm_history[i])
            ax.fill_between(step_list, bottom, bottom + vals,
                            alpha=0.7, color=colors[i], label=arm_names[i])
            bottom += vals
        ax.set_xlabel("Training Step")
        ax.set_ylabel("Selection Probability")
        ax.set_title("PPO Action Distribution Over Time")
        ax.legend(loc="center left", bbox_to_anchor=(1.02, 0.5), fontsize=8)
        ax.set_ylim(0, 1)
    else:
        ax.text(0.5, 0.5, "No arm_distribution data", ha="center", va="center",
                transform=ax.transAxes)
        ax.set_title("PPO Action Distribution Over Time")

    fig.suptitle("PPO Training Diagnostics", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(output_dir / f"fig9_ppo_training.{ext}")
    plt.close(fig)


def plot_summary_table(groups: dict, output_dir: Path, ext: str):
    """Fig 10: Summary comparison table rendered as a figure."""
    columns = ["Policy", "Iterations", "Cum. Reward", "Reward/Iter",
               "Bugs", "Buckets", "Top Arm"]
    arm_names = ["splice", "reg", "const", "ins", "del", "dup", "swap", "mnem"]
    rows = []
    for policy, runs in groups.items():
        if not runs or not runs[0]:
            continue
        last = runs[0][-1]
        iters = last.get("iteration", 0)
        cum_r = last.get("cumulative_reward", 0)
        bugs = last.get("bug_count", 0)
        buckets = last.get("unique_bucket_ids", 0)
        pulls = last.get("arm_pulls", [0] * 8)
        total_pulls = max(sum(pulls[:8]), 1)
        top_idx = int(np.argmax(pulls[:8]))
        top_frac = pulls[top_idx] / total_pulls
        label = POLICY_LABELS.get(policy, policy)
        rows.append([
            label, str(iters), f"{cum_r:.1f}",
            f"{cum_r / max(iters, 1):.3f}", str(bugs), str(buckets),
            f"{arm_names[top_idx]} ({top_frac:.0%})",
        ])

    if not rows:
        return

    fig, ax = plt.subplots(figsize=(12, 1 + 0.5 * len(rows)))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=columns, loc="center",
                     cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.6)
    for j in range(len(columns)):
        table[0, j].set_facecolor("#4a90d9")
        table[0, j].set_text_props(color="white", fontweight="bold")
    for i in range(1, len(rows) + 1):
        color = "#f0f0f0" if i % 2 == 0 else "white"
        for j in range(len(columns)):
            table[i, j].set_facecolor(color)

    fig.suptitle("Experiment Results Summary", fontsize=13, fontweight="bold", y=0.95)
    fig.tight_layout()
    fig.savefig(output_dir / f"fig10_summary.{ext}")
    plt.close(fig)


def generate_all(
    metrics_dir: Path,
    output_dir: Path,
    log_dir: Path | None = None,
    paper_mode: bool = False,
):
    ext = "pdf" if paper_mode else "png"
    _setup_style(paper_mode)
    output_dir.mkdir(parents=True, exist_ok=True)

    groups = load_metrics(metrics_dir)
    if not groups:
        print(f"No metrics files found in {metrics_dir}")
        return

    print(f"Found policies: {list(groups.keys())}")
    print(f"Generating figures to {output_dir}/")

    plot_cumulative_reward(groups, output_dir, ext)
    plot_bucket_coverage(groups, output_dir, ext)
    plot_bug_discovery(groups, output_dir, ext)
    plot_arm_heatmap(groups, output_dir, ext)
    plot_arm_comparison(groups, output_dir, ext)
    plot_signatures_over_time(groups, output_dir, ext)
    plot_reward_rate(groups, output_dir, ext)
    plot_learning_curve(groups, output_dir, ext)
    plot_summary_table(groups, output_dir, ext)

    if log_dir:
        plot_entropy(output_dir, log_dir, ext)
        plot_ppo_training(output_dir, log_dir, ext)

    print("Done.")


def main():
    parser = argparse.ArgumentParser(description="Beak-Fuzz RL Visualization")
    parser.add_argument("--metrics-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("output/figures"))
    parser.add_argument("--log-dir", type=Path, default=None)
    parser.add_argument("--paper-mode", action="store_true")
    args = parser.parse_args()

    generate_all(
        args.metrics_dir, args.output_dir,
        log_dir=args.log_dir, paper_mode=args.paper_mode,
    )


if __name__ == "__main__":
    main()
