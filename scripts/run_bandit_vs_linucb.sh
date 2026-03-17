#!/usr/bin/env bash
# Compare Bandit (no context) vs LinUCB (contextual RL).
# No Python server needed — both are pure Rust.
#
# Usage:
#   ./scripts/run_bandit_vs_linucb.sh
#   ./scripts/run_bandit_vs_linucb.sh --iters 5000

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ITERS=500
METRICS_INTERVAL=50
INITIAL_LIMIT=500
TIMEOUT_MS=500
MAX_INSTRUCTIONS=32

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
COMMON_ARGS="--iters $ITERS --metrics-interval $METRICS_INTERVAL --initial-limit $INITIAL_LIMIT --timeout-ms $TIMEOUT_MS --max-instructions $MAX_INSTRUCTIONS"

echo "============================================"
echo "  Bandit vs LinUCB (No Python, Pure Rust)"
echo "  iters=$ITERS  seeds=$INITIAL_LIMIT"
echo "============================================"
echo ""

OPENVM_SRC="$PROJECT_ROOT/beak-py/out/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/openvm-src"
if [ ! -d "$OPENVM_SRC" ]; then
    echo "[0/3] Installing OpenVM source (first time)..."
    cd "$PROJECT_ROOT" && make openvm-install COMMIT=bmk-regzero
fi
echo "[0/3] Building..."
cd "$BACKEND_DIR" && CARGO_TARGET_DIR="$BACKEND_DIR/target" cargo build --release --bin beak-fuzz-rl 2>&1 | grep -E "Compiling|Finished|error" || true
cd "$PROJECT_ROOT"

rm -f storage/fuzzing_seeds/*-run1-*
rm -rf output/figures/*
mkdir -p output/figures

echo ""
echo "[1/3] Running UCB1 Bandit ($ITERS iters)..."
START=$(date +%s)
FAST_TEST=1 "$FUZZ_BIN" --policy bandit $COMMON_ARGS --output-prefix bandit-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -3 || true
echo "  Done in $(( $(date +%s) - START ))s"

echo ""
echo "[2/3] Running LinUCB ($ITERS iters)..."
START=$(date +%s)
FAST_TEST=1 "$FUZZ_BIN" --policy linucb $COMMON_ARGS --output-prefix linucb-run1 2>&1 | grep -E "^\[LOOP1\]\[iter.*/${ITERS}\]|^Wrote" | tail -3 || true
echo "  Done in $(( $(date +%s) - START ))s"

echo ""
echo "[3/3] Generating plots..."
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.visualize \
    --metrics-dir storage/fuzzing_seeds \
    --output-dir output/figures

echo ""
echo "============================================"
echo "  Results: Bandit vs LinUCB"
echo "============================================"
for f in storage/fuzzing_seeds/*-run1-*-metrics.jsonl; do
    tail -1 "$f" | python3 -c "
import json, sys
d = json.load(sys.stdin)
p = d['arm_pulls']
total = max(sum(p), 1)
top3 = sorted(zip([x/total for x in p], ['splice','reg','const','ins','del','dup','swap','mnem']), reverse=True)[:3]
top_str = ', '.join(f'{name} {pct:.0%}' for pct, name in top3)
r_per_i = d['cumulative_reward'] / max(d['iteration'], 1)
print(f\"  {d['policy_type']:8s}  iters={d['iteration']:5d}  reward/iter={r_per_i:.3f}  bugs={d['bug_count']:4d}  top: {top_str}\")
"
done
echo "============================================"
open output/figures/
