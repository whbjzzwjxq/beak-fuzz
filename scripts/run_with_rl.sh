#!/usr/bin/env bash
# Launch RL agent server + Rust fuzzer with RL policy.
#
# Usage:
#   ./scripts/run_with_rl.sh [extra-args-for-fuzz-binary...]
#
# Examples:
#   # Quick test (100 iters, metrics every 10 iters):
#   ./scripts/run_with_rl.sh --iters 100 --metrics-interval 10
#
#   # Full run:
#   ./scripts/run_with_rl.sh --iters 5000 --metrics-interval 50
#
# Environment variables:
#   BEAK_RL_SOCKET    - Unix socket path (default: /tmp/beak-rl.sock)
#   BEAK_RL_LOG_DIR   - RL server log directory (default: output/rl_logs)
#   BEAK_RL_CKPT_DIR  - RL checkpoint directory (default: output/rl_checkpoints)
#   FUZZ_BIN          - Path to fuzz binary (default: auto-detect via cargo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

SOCKET_PATH="${BEAK_RL_SOCKET:-/tmp/beak-rl.sock}"
LOG_DIR="${BEAK_RL_LOG_DIR:-output/rl_logs}"
CKPT_DIR="${BEAK_RL_CKPT_DIR:-output/rl_checkpoints}"

JOLT_PROJECT="$PROJECT_ROOT/projects/jolt-e9caa23565dbb13019afe61a2c95f51d1999e286"

# Build the RL-enabled fuzzer if no explicit FUZZ_BIN given.
if [ -z "${FUZZ_BIN:-}" ]; then
    echo "[run_with_rl] building beak-fuzz-rl (release)..." >&2
    cd "$JOLT_PROJECT" && CARGO_TARGET_DIR="$JOLT_PROJECT/target" cargo build --release --bin beak-fuzz-rl
    cd "$PROJECT_ROOT"
    FUZZ_BIN="$JOLT_PROJECT/target/release/beak-fuzz-rl"
fi

cleanup() {
    echo "[run_with_rl] shutting down RL server (pid=$RL_PID)..." >&2
    kill "$RL_PID" 2>/dev/null || true
    wait "$RL_PID" 2>/dev/null || true
    rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

echo "[run_with_rl] starting RL agent server on $SOCKET_PATH..." >&2
PYTHONPATH="$PROJECT_ROOT/beak-py" python3 -m rl.server \
    --socket "$SOCKET_PATH" \
    --log-dir "$LOG_DIR" \
    --checkpoint-dir "$CKPT_DIR" &
RL_PID=$!

echo "[run_with_rl] waiting for socket..." >&2
for i in $(seq 1 30); do
    if [ -S "$SOCKET_PATH" ]; then
        break
    fi
    sleep 0.2
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "[run_with_rl] ERROR: RL server failed to start" >&2
    exit 1
fi

echo "[run_with_rl] starting fuzzer with --policy=rl..." >&2
"$FUZZ_BIN" \
    --policy rl \
    --rl-socket-path "$SOCKET_PATH" \
    "$@"
