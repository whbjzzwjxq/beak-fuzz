#!/usr/bin/env bash
# Plan B: 1000 iterations with aggressive PPO hyperparameters for fast convergence.
#
# Compared to Plan A (3000 iters, default config), this plan:
#   - warmup_steps:   200 → 50   (minimize random exploration waste)
#   - update_every:    32 → 16   (2x more frequent policy updates)
#   - learning_rate: 3e-4 → 1e-3 (faster gradient steps)
#   - hidden_dims: [64,64] → [32] (fewer params, easier to learn)
#   - batch_size:      16 → 8    (match smaller update_every)
#
# Usage:
#   ./scripts/run_experiments_fast.sh
#   ./scripts/run_experiments_fast.sh --iters 500

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ITERS=1000
METRICS_INTERVAL=10
INITIAL_LIMIT=50
TIMEOUT_MS=10000
MAX_INSTRUCTIONS=64

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iters) ITERS="$2"; shift 2 ;;
        --initial-limit) INITIAL_LIMIT="$2"; shift 2 ;;
        --max-instructions) MAX_INSTRUCTIONS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

BACKEND_DIR="$PROJECT_ROOT/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5"
FUZZ_BIN="$BACKEND_DIR/target/release/beak-fuzz-rl"
SOCKET_PATH="/tmp/beak-rl.sock"
CONFIG_FILE="$PROJECT_ROOT/beak-py/rl/config.py"
COMMON_ARGS="--iters $ITERS --metrics-interval $METRICS_INTERVAL --initial-limit $INITIAL_LIMIT --timeout-ms $TIMEOUT_MS --max-instructions $MAX_INSTRUCTIONS"

echo "============================================"
echo "  Beak-Fuzz RL — Plan B (Fast Convergence)"
echo "  iters=$ITERS  seeds=$INITIAL_LIMIT  max_insn=$MAX_INSTRUCTIONS"
echo "============================================"
echo ""

# Step 0: Build
OPENVM_SRC="$PROJECT_ROOT/beak-py/out/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/openvm-src"
if [ ! -d "$OPENVM_SRC" ]; then
    echo "[0/6] Installing OpenVM source (first time)..."
    cd "$PROJECT_ROOT" && make openvm-install COMMIT=bmk-regzero
fi
echo "[0/6] Building beak-fuzz-rl..."
cd "$BACKEND_DIR" && CARGO_TARGET_DIR="$BACKEND_DIR/target" cargo build --release --bin beak-fuzz-rl 2>&1 | grep -E "Compiling|Finished|error" || true
cd "$PROJECT_ROOT"
echo ""

# Step 1: Backup config & apply Plan B hyperparameters
echo "[1/6] Applying Plan B hyperparameters..."
cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

cat > "$CONFIG_FILE" << 'PYEOF'
"""Hyperparameter configuration for RL agents — Plan B (fast convergence)."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MutatorAgentConfig:
    num_arms: int = 8
    state_dim: int = 23
    hidden_dims: list[int] = field(default_factory=lambda: [32])
    learning_rate: float = 1e-3
    gamma: float = 0.99
    gae_lambda: float = 0.95
    clip_epsilon: float = 0.2
    entropy_coef: float = 0.2
    value_coef: float = 0.5
    max_grad_norm: float = 0.5
    update_every: int = 16
    ppo_epochs: int = 4
    batch_size: int = 8
    warmup_steps: int = 50


@dataclass
class SchedulerAgentConfig:
    state_dim: int = 15
    hidden_dims: list[int] = field(default_factory=lambda: [64, 64])
    learning_rate: float = 3e-4
    gamma: float = 0.99
    update_every: int = 64
    warmup_steps: int = 500


@dataclass
class InjectionAgentConfig:
    state_dim: int = 10
    max_step: int = 1000
    num_step_bins: int = 50
    hidden_dims: list[int] = field(default_factory=lambda: [64, 64])
    learning_rate: float = 1e-3
    gamma: float = 0.99
    epsilon_start: float = 1.0
    epsilon_end: float = 0.05
    epsilon_decay: int = 5000
    buffer_size: int = 10000
    batch_size: int = 32
    target_update_every: int = 100
    warmup_steps: int = 200


@dataclass
class ServerConfig:
    socket_path: str = "/tmp/beak-rl.sock"
    log_dir: str = "output/rl_logs"
    checkpoint_dir: str = "output/rl_checkpoints"
    checkpoint_every: int = 1000
    tensorboard: bool = True
    mutator: MutatorAgentConfig = field(default_factory=MutatorAgentConfig)
    scheduler: SchedulerAgentConfig = field(default_factory=SchedulerAgentConfig)
    injection: InjectionAgentConfig = field(default_factory=InjectionAgentConfig)
PYEOF

restore_config() {
    if [ -f "${CONFIG_FILE}.bak" ]; then
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
        echo "  (Config restored to Plan A defaults)"
    fi
}
trap restore_config EXIT

echo "  Applied: hidden=[32], lr=1e-3, update_every=16, batch=8, warmup=50"
echo ""

# Step 2: Clean old data
echo "[2/6] Cleaning old experiment data..."
rm -f storage/fuzzing_seeds/*-run1-*
rm -f output/rl_logs/rl_server_metrics.jsonl
rm -rf output/figures/*
mkdir -p output/figures output/rl_logs output/rl_checkpoints
echo ""

# Step 3: Bandit
echo "[3/6] Running Bandit baseline ($ITERS iters)..."
START=$(date +%s)
"$FUZZ_BIN" --policy bandit $COMMON_ARGS --output-prefix bandit-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true
ELAPSED=$(( $(date +%s) - START ))
echo "  Done in ${ELAPSED}s"
echo ""

# Step 4: LinUCB
echo "[4/6] Running LinUCB ($ITERS iters)..."
START=$(date +%s)
"$FUZZ_BIN" --policy linucb $COMMON_ARGS --output-prefix linucb-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true
ELAPSED=$(( $(date +%s) - START ))
echo "  Done in ${ELAPSED}s"
echo ""

# Step 5: PPO
echo "[5/6] Running PPO with Plan B config ($ITERS iters)..."
START=$(date +%s)

rm -f "$SOCKET_PATH"
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.server \
    --socket "$SOCKET_PATH" \
    --log-dir output/rl_logs \
    --checkpoint-dir output/rl_checkpoints &
RL_PID=$!

for i in $(seq 1 30); do
    [ -S "$SOCKET_PATH" ] && break
    sleep 0.2
done
if [ ! -S "$SOCKET_PATH" ]; then
    echo "  ERROR: RL server failed to start"
    kill "$RL_PID" 2>/dev/null || true
    exit 1
fi

"$FUZZ_BIN" --policy rl --rl-socket-path "$SOCKET_PATH" $COMMON_ARGS --output-prefix rl-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true

kill "$RL_PID" 2>/dev/null || true
wait "$RL_PID" 2>/dev/null || true
rm -f "$SOCKET_PATH"
ELAPSED=$(( $(date +%s) - START ))
PPO_COMPLETED=$( [ -f storage/fuzzing_seeds/rl-run1-*-metrics.jsonl ] && tail -1 storage/fuzzing_seeds/rl-run1-*-metrics.jsonl | python3 -c "import json,sys; print(json.load(sys.stdin).get('iteration',0))" 2>/dev/null || echo 0 )
echo "  Done in ${ELAPSED}s (completed $PPO_COMPLETED/$ITERS iters)"
echo ""

# Step 6: Generate plots
echo "[6/6] Generating comparison plots..."
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.visualize \
    --metrics-dir storage/fuzzing_seeds \
    --output-dir output/figures \
    --log-dir output/rl_logs
echo ""

# Summary
echo "============================================"
echo "  Plan B Results Summary"
echo "============================================"
echo "  PPO config: hidden=[32], lr=1e-3, update_every=16, batch=8, warmup=50"
echo "  Expected PPO updates: ~$(( (ITERS - 50) / 16 )) policy updates"
echo ""
for f in storage/fuzzing_seeds/*-run1-*-metrics.jsonl; do
    tail -1 "$f" | python3 -c "
import json, sys
d = json.load(sys.stdin)
p = d['arm_pulls']
total = max(sum(p), 1)
top3 = sorted(zip([x/total for x in p], ['splice','reg','const','ins','del','dup','swap','mnem']), reverse=True)[:3]
top_str = ', '.join(f'{name} {pct:.0%}' for pct, name in top3)
print(f\"  {d['policy_type']:8s}  reward={d['cumulative_reward']:8.1f}  bugs={d['bug_count']:4d}  top: {top_str}\")
"
done
echo ""
echo "Figures saved to: output/figures/"
echo "============================================"
open output/figures/
