#!/usr/bin/env bash
# Run all RL experiments (Bandit, LinUCB, PPO) and generate comparison plots.
#
# Usage:
#   ./scripts/run_all_experiments.sh              # default 1000 iters
#   ./scripts/run_all_experiments.sh --iters 2000  # custom iters
#
# Output:
#   storage/fuzzing_seeds/*-metrics.jsonl   (raw data)
#   output/figures/*.png                    (comparison plots)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Defaults matching OpenVM Makefile (make openvm-fuzz)
ITERS=500
METRICS_INTERVAL=50
INITIAL_LIMIT=500
TIMEOUT_MS=500
MAX_INSTRUCTIONS=32

# Parse optional --iters override
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
COMMON_ARGS="--iters $ITERS --metrics-interval $METRICS_INTERVAL --initial-limit $INITIAL_LIMIT --timeout-ms $TIMEOUT_MS --max-instructions $MAX_INSTRUCTIONS"

echo "============================================"
echo "  Beak-Fuzz RL Experiment Suite"
echo "  iters=$ITERS  seeds=$INITIAL_LIMIT  max_insn=$MAX_INSTRUCTIONS"
echo "============================================"
echo ""

# Step 0: Ensure OpenVM source is installed, then build
OPENVM_SRC="$PROJECT_ROOT/beak-py/out/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/openvm-src"
if [ ! -d "$OPENVM_SRC" ]; then
    echo "[0/5] Installing OpenVM source (first time)..."
    cd "$PROJECT_ROOT" && make openvm-install COMMIT=bmk-regzero
fi
echo "[0/5] Building beak-fuzz-rl..."
cd "$BACKEND_DIR" && CARGO_TARGET_DIR="$BACKEND_DIR/target" cargo build --release --bin beak-fuzz-rl 2>&1 | grep -E "Compiling|Finished|error" || true
cd "$PROJECT_ROOT"
echo ""

# Step 1: Clean old data
echo "[1/5] Cleaning old experiment data..."
rm -f storage/fuzzing_seeds/*-run1-*
rm -f output/rl_logs/rl_server_metrics.jsonl
rm -rf output/figures/*
mkdir -p output/figures output/rl_logs output/rl_checkpoints
echo ""

# Step 2: Random (pure baseline)
echo "[2/6] Running Random baseline ($ITERS iters)..."
START=$(date +%s)
FAST_TEST=1 "$FUZZ_BIN" --policy random $COMMON_ARGS --output-prefix random-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true
ELAPSED=$(( $(date +%s) - START ))
echo "  Done in ${ELAPSED}s"
echo ""

# Step 3: Bandit (UCB1)
echo "[3/6] Running UCB1 Bandit ($ITERS iters)..."
START=$(date +%s)
FAST_TEST=1 "$FUZZ_BIN" --policy bandit $COMMON_ARGS --output-prefix bandit-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true
ELAPSED=$(( $(date +%s) - START ))
echo "  Done in ${ELAPSED}s"
echo ""

# Step 4: LinUCB
echo "[4/6] Running LinUCB ($ITERS iters)..."
START=$(date +%s)
FAST_TEST=1 "$FUZZ_BIN" --policy linucb $COMMON_ARGS --output-prefix linucb-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true
ELAPSED=$(( $(date +%s) - START ))
echo "  Done in ${ELAPSED}s"
echo ""

# Step 4: PPO
echo "[5/6] Running PPO with RL server ($ITERS iters)..."
START=$(date +%s)

rm -f "$SOCKET_PATH"
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.server \
    --socket "$SOCKET_PATH" \
    --log-dir output/rl_logs \
    --checkpoint-dir output/rl_checkpoints &
RL_PID=$!

# Wait for socket
for i in $(seq 1 30); do
    [ -S "$SOCKET_PATH" ] && break
    sleep 0.2
done
if [ ! -S "$SOCKET_PATH" ]; then
    echo "  ERROR: RL server failed to start"
    kill "$RL_PID" 2>/dev/null || true
    exit 1
fi

FAST_TEST=1 "$FUZZ_BIN" --policy rl --rl-socket-path "$SOCKET_PATH" $COMMON_ARGS --output-prefix rl-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -5 || true

kill "$RL_PID" 2>/dev/null || true
wait "$RL_PID" 2>/dev/null || true
rm -f "$SOCKET_PATH"
ELAPSED=$(( $(date +%s) - START ))
PPO_COMPLETED=$( [ -f storage/fuzzing_seeds/rl-run1-*-metrics.jsonl ] && tail -1 storage/fuzzing_seeds/rl-run1-*-metrics.jsonl | python3 -c "import json,sys; print(json.load(sys.stdin).get('iteration',0))" 2>/dev/null || echo 0 )
echo "  Done in ${ELAPSED}s (completed $PPO_COMPLETED/$ITERS iters)"
echo ""

# Step 5: Generate plots
echo "[6/6] Generating comparison plots..."
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.visualize \
    --metrics-dir storage/fuzzing_seeds \
    --output-dir output/figures \
    --log-dir output/rl_logs
echo ""

# Summary
echo "============================================"
echo "  Results Summary"
echo "============================================"
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
