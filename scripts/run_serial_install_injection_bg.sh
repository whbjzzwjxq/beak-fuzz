#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BEAK_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
RUNNER="$SCRIPT_DIR/run_serial_install_injection.sh"

RUN_ROOT="${RUN_ROOT:-$BEAK_ROOT/out/serial-install-injection}"
PID_FILE="${PID_FILE:-$RUN_ROOT/serial-install-injection.pid}"
CMD_FILE="${CMD_FILE:-$RUN_ROOT/serial-install-injection.cmd}"
LATEST_LOG_FILE="${LATEST_LOG_FILE:-$RUN_ROOT/latest-nohup-log.txt}"

usage() {
    cat <<'EOF'
Usage:
  run_serial_install_injection_bg.sh start [runner-args...]
  run_serial_install_injection_bg.sh status
  run_serial_install_injection_bg.sh stop

Examples:
  run_serial_install_injection_bg.sh start
  run_serial_install_injection_bg.sh start --only-commit 7f643da1
  run_serial_install_injection_bg.sh status
  run_serial_install_injection_bg.sh stop

Defaults inherited by the runner:
  THREADS=8
  CPU_SET=0-7
  SOFT_TIMEOUT_SECONDS=14400
  SEED_TIMEOUT_MS=60000
  MEMORY_LIMIT_GB=40
  ORACLE_PRECHECK_MAX_STEPS=32
EOF
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "missing required command: $cmd" >&2
        exit 1
    }
}

quote_cmd() {
    local out=()
    local arg
    for arg in "$@"; do
        out+=("$(printf '%q' "$arg")")
    done
    printf '%s ' "${out[@]}"
    printf '\n'
}

is_running() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null
}

read_pid() {
    if [[ -f "$PID_FILE" ]]; then
        tr -d '[:space:]' <"$PID_FILE"
    fi
}

cmd_status() {
    local pid
    pid=$(read_pid || true)
    if [[ -z "${pid:-}" ]]; then
        echo "not running"
        return 1
    fi
    if is_running "$pid"; then
        echo "running"
        echo "pid: $pid"
        if [[ -f "$LATEST_LOG_FILE" ]]; then
            echo "log: $(cat "$LATEST_LOG_FILE")"
        fi
        if [[ -f "$CMD_FILE" ]]; then
            echo "cmd: $(cat "$CMD_FILE")"
        fi
        return 0
    fi
    echo "stale pid file: $pid"
    rm -f "$PID_FILE"
    return 1
}

cmd_stop() {
    local pid
    pid=$(read_pid || true)
    if [[ -z "${pid:-}" ]]; then
        echo "not running"
        return 0
    fi
    if ! is_running "$pid"; then
        echo "stale pid file: $pid"
        rm -f "$PID_FILE"
        return 0
    fi
    kill "$pid"
    echo "sent SIGTERM to pid $pid"
}

cmd_start() {
    local pid
    pid=$(read_pid || true)
    if [[ -n "${pid:-}" ]] && is_running "$pid"; then
        echo "already running with pid $pid" >&2
        if [[ -f "$LATEST_LOG_FILE" ]]; then
            echo "log: $(cat "$LATEST_LOG_FILE")" >&2
        fi
        exit 1
    fi

    mkdir -p "$RUN_ROOT"
    local ts
    ts=$(date +"%Y%m%d-%H%M%S")
    local launch_log="$RUN_ROOT/nohup-$ts.log"

    local -a cmd=(
        env
        "THREADS=${THREADS:-8}"
        "CPU_SET=${CPU_SET:-0-7}"
        "SOFT_TIMEOUT_SECONDS=${SOFT_TIMEOUT_SECONDS:-14400}"
        "KILL_GRACE_SECONDS=${KILL_GRACE_SECONDS:-30}"
        "SEED_TIMEOUT_MS=${SEED_TIMEOUT_MS:-${WORKER_TIMEOUT_MS:-${CLI_TIMEOUT_MS:-60000}}}"
        "MEMORY_LIMIT_GB=${MEMORY_LIMIT_GB:-40}"
        "ORACLE_PRECHECK_MAX_STEPS=${ORACLE_PRECHECK_MAX_STEPS:-32}"
        "UV_CACHE_DIR=${UV_CACHE_DIR:-/tmp/uv-cache}"
        "ARGUZZ_REPO_CACHE=${ARGUZZ_REPO_CACHE:-/tmp/zkvm-repos}"
        bash
        "$RUNNER"
        "$@"
    )

    pid=$(
        python3 - "$launch_log" "${cmd[@]}" <<'PY'
import subprocess
import sys

log_path = sys.argv[1]
cmd = sys.argv[2:]

with open(log_path, "ab", buffering=0) as logf:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
print(proc.pid)
PY
    )
    printf '%s\n' "$pid" >"$PID_FILE"
    quote_cmd "${cmd[@]}" >"$CMD_FILE"
    printf '%s\n' "$launch_log" >"$LATEST_LOG_FILE"

    echo "started"
    echo "pid: $pid"
    echo "log: $launch_log"
}

require_cmd bash
require_cmd date
require_cmd python3

subcmd="${1:-}"
case "$subcmd" in
    start)
        shift
        cmd_start "$@"
        ;;
    status)
        shift
        [[ $# -eq 0 ]] || { usage >&2; exit 1; }
        cmd_status
        ;;
    stop)
        shift
        [[ $# -eq 0 ]] || { usage >&2; exit 1; }
        cmd_stop
        ;;
    -h|--help|"")
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
