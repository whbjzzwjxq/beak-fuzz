#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BEAK_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

THREADS="${THREADS:-8}"
CPU_SET="${CPU_SET:-0-7}"
SOFT_TIMEOUT_SECONDS="${SOFT_TIMEOUT_SECONDS:-14400}"
KILL_GRACE_SECONDS="${KILL_GRACE_SECONDS:-30}"
UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"
ARGUZZ_REPO_CACHE="${ARGUZZ_REPO_CACHE:-/tmp/zkvm-repos}"
SEEDS_JSONL="${SEEDS_JSONL:-$BEAK_ROOT/storage/fuzzing_seeds/initial.jsonl}"
SEED_TIMEOUT_MS="${SEED_TIMEOUT_MS:-${WORKER_TIMEOUT_MS:-${CLI_TIMEOUT_MS:-60000}}}"
MEMORY_LIMIT_GB="${MEMORY_LIMIT_GB:-40}"
MEMORY_LIMIT_BYTES="${MEMORY_LIMIT_BYTES:-$((MEMORY_LIMIT_GB * 1024 * 1024 * 1024))}"
INITIAL_LIMIT="${INITIAL_LIMIT:-0}"
MAX_INSTRUCTIONS="${MAX_INSTRUCTIONS:-256}"
ORACLE_PRECHECK_MAX_STEPS="${ORACLE_PRECHECK_MAX_STEPS:-32}"
SEMANTIC_WINDOW_BEFORE="${SEMANTIC_WINDOW_BEFORE:-16}"
SEMANTIC_WINDOW_AFTER="${SEMANTIC_WINDOW_AFTER:-64}"
SEMANTIC_STEP_STRIDE="${SEMANTIC_STEP_STRIDE:-1}"
SEMANTIC_MAX_TRIALS="${SEMANTIC_MAX_TRIALS:-64}"
FAST_TEST="${FAST_TEST:-0}"

RUN_ROOT="${RUN_ROOT:-$BEAK_ROOT/out/serial-install-injection}"
LOG_ROOT="${LOG_ROOT:-$RUN_ROOT/logs}"
SUMMARY_PATH="${SUMMARY_PATH:-$RUN_ROOT/summary.tsv}"

PRINT_COMMANDS=0
SKIP_INSTALL=0
ONLY_COMMITS=()
EXCLUDE_COMMITS=()

usage() {
    cat <<'EOF'
Usage:
  run_serial_install_injection.sh [--print-commands] [--skip-install] [--only-commit <sha-or-prefix>] [--exclude-commit <sha-or-prefix>]

Defaults:
  - serial execution
  - THREADS=8
  - CPU_SET=0-7
  - SOFT_TIMEOUT_SECONDS=14400 (4 hours)
  - SEED_TIMEOUT_MS=60000
  - MEMORY_LIMIT_GB=40
  - SEEDS_JSONL=<beak>/storage/fuzzing_seeds/initial.jsonl
  - INITIAL_LIMIT=0 (run all initial seeds)
  - MAX_INSTRUCTIONS=256
  - ORACLE_PRECHECK_MAX_STEPS=32
  - SEMANTIC_WINDOW_BEFORE=16
  - SEMANTIC_WINDOW_AFTER=64
  - SEMANTIC_STEP_STRIDE=1
  - SEMANTIC_MAX_TRIALS=64
  - FAST_TEST=0
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

cpu_prefix_array() {
    if command -v taskset >/dev/null 2>&1; then
        printf '%s\0' taskset -c "$CPU_SET"
    fi
}

memory_prefix_array() {
    if command -v prlimit >/dev/null 2>&1 && [[ "$MEMORY_LIMIT_BYTES" -gt 0 ]]; then
        printf '%s\0' prlimit "--as=$MEMORY_LIMIT_BYTES"
    fi
}

common_env_array() {
    local path_prefix="$PATH"
    if [[ -d "$HOME/.local/bin" ]]; then
        path_prefix="$HOME/.local/bin:$path_prefix"
    fi

    printf '%s\0' \
        env \
        "PATH=$path_prefix" \
        "UV_CACHE_DIR=$UV_CACHE_DIR" \
        "ARGUZZ_REPO_CACHE=$ARGUZZ_REPO_CACHE" \
        "CARGO_BUILD_JOBS=$THREADS" \
        "RAYON_NUM_THREADS=$THREADS" \
        "OMP_NUM_THREADS=$THREADS" \
        "TOKIO_WORKER_THREADS=$THREADS" \
        "NUM_JOBS=$THREADS" \
        "CMAKE_BUILD_PARALLEL_LEVEL=$THREADS" \
        "FAST_TEST=$FAST_TEST"
}

run_and_log() {
    local log_file="$1"
    shift
    mkdir -p "$(dirname -- "$log_file")"
    : >"$log_file"
    {
        echo "[cmd] $(quote_cmd "$@")"
        "$@"
    } 2>&1 | tee -a "$log_file"
}

run_with_reaper() {
    local timeout_seconds="$1"
    local grace_seconds="$2"
    local log_file="$3"
    shift 3

    mkdir -p "$(dirname -- "$log_file")"
    : >"$log_file"
    echo "[cmd] $(quote_cmd "$@")" | tee -a "$log_file"

    setsid "$@" > >(tee -a "$log_file") 2>&1 &
    local pid=$!
    local pgid=$pid
    local start_ts=$SECONDS

    while kill -0 "$pid" 2>/dev/null; do
        if (( SECONDS - start_ts >= timeout_seconds )); then
            echo "[reaper] ${timeout_seconds}s reached, sending SIGTERM to process group $pgid" \
                | tee -a "$log_file"
            kill -TERM "-$pgid" 2>/dev/null || true

            local grace_start=$SECONDS
            while kill -0 "$pid" 2>/dev/null && (( SECONDS - grace_start < grace_seconds )); do
                sleep 1
            done

            if kill -0 "$pid" 2>/dev/null; then
                echo "[reaper] grace period expired, sending SIGKILL to process group $pgid" \
                    | tee -a "$log_file"
                pkill -KILL -P "$pid" 2>/dev/null || true
                kill -KILL "-$pgid" 2>/dev/null || true
            fi

            wait "$pid" || true
            return 124
        fi
        sleep 5
    done

    wait "$pid"
}

target_ids() {
    cat <<'EOF'
openvm-336f1a47
openvm-d7eab708
openvm-f038f61d
pico-45e74ccd
sp1-39ab52fc
sp1-7f643da1
sp1-811a3f2c
sp1-3561f006
sp1-fb38df2c
jolt-e9caa235
nexus-636ccb36
risc0-98387806
risc0-c0db0713
EOF
}

target_commit() {
    case "$1" in
        openvm-336f1a47) echo "336f1a475e5aa3513c4c5a266399f4128c119bba" ;;
        openvm-d7eab708) echo "d7eab708f43487b2e7c00524ffd611f835e8e6b5" ;;
        openvm-f038f61d) echo "f038f61d21db3aecd3029e1a23ba1ba0bb314800" ;;
        pico-45e74ccd) echo "45e74ccd62758c6d67239913956e749adaba261c" ;;
        sp1-39ab52fc) echo "39ab52fce38172c9d23feed7248198dc14c164a9" ;;
        sp1-7f643da1) echo "7f643da16813af4c0fbaad4837cd7409386cf38c" ;;
        sp1-811a3f2c) echo "811a3f2c03914088c7c9e1774266934a3f9f5359" ;;
        sp1-3561f006) echo "3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1" ;;
        sp1-fb38df2c) echo "fb38df2c4e963ef1d3a6f3be0ff62ea92bb3df13" ;;
        jolt-e9caa235) echo "e9caa23565dbb13019afe61a2c95f51d1999e286" ;;
        nexus-636ccb36) echo "636ccb360d0f4ae657ae4bb64e1e275ccec8826" ;;
        risc0-98387806) echo "98387806fe8348d87e32974468c6f35853356ad5" ;;
        risc0-c0db0713) echo "c0db0713671c8ec467b3efc26b22a0b0591897ff" ;;
        *) echo "unknown target: $1" >&2; exit 1 ;;
    esac
}

target_project_dir() {
    local commit
    commit=$(target_commit "$1")
    case "$1" in
        openvm-*) echo "$BEAK_ROOT/projects/openvm-$commit" ;;
        pico-*) echo "$BEAK_ROOT/projects/pico-$commit" ;;
        sp1-*) echo "$BEAK_ROOT/projects/sp1-$commit" ;;
        jolt-*) echo "$BEAK_ROOT/projects/jolt-$commit" ;;
        nexus-*) echo "$BEAK_ROOT/projects/nexus-$commit" ;;
        risc0-*) echo "$BEAK_ROOT/projects/risc0-$commit" ;;
        *) echo "unknown target: $1" >&2; exit 1 ;;
    esac
}

target_install_triplet() {
    local commit
    commit=$(target_commit "$1")
    case "$1" in
        openvm-*) printf '%s\0%s\0%s\0' openvm-install COMMIT "$commit" ;;
        pico-*) printf '%s\0%s\0%s\0' pico-install PICO_COMMIT "$commit" ;;
        sp1-*) printf '%s\0%s\0%s\0' sp1-install SP1_COMMIT "$commit" ;;
        jolt-*) printf '%s\0%s\0%s\0' jolt-install JOLT_COMMIT "$commit" ;;
        nexus-*) printf '%s\0%s\0%s\0' nexus-install NEXUS_COMMIT "$commit" ;;
        risc0-*) printf '%s\0%s\0%s\0' risc0-install RISC0_COMMIT "$commit" ;;
        *) echo "unknown target: $1" >&2; exit 1 ;;
    esac
}

matches_filters() {
    local target_id="$1"
    local commit="$2"
    local needle

    if [[ "${#ONLY_COMMITS[@]}" -gt 0 ]]; then
        local matched=1
        for needle in "${ONLY_COMMITS[@]}"; do
            if [[ "$commit" == "$needle"* ]] || [[ "$needle" == "$commit"* ]] \
                || [[ "$target_id" == "$needle"* ]] || [[ "$needle" == "$target_id"* ]]; then
                matched=0
                break
            fi
        done
        if [[ "$matched" -ne 0 ]]; then
            return 1
        fi
    fi

    for needle in "${EXCLUDE_COMMITS[@]}"; do
        if [[ "$commit" == "$needle"* ]] || [[ "$needle" == "$commit"* ]] \
            || [[ "$target_id" == "$needle"* ]] || [[ "$needle" == "$target_id"* ]]; then
            return 1
        fi
    done

    return 0
}

build_install_cmd() {
    local target_id="$1"
    local -a cmd=()
    mapfile -d '' -t prefix < <(cpu_prefix_array)
    mapfile -d '' -t memory_prefix < <(memory_prefix_array)
    mapfile -d '' -t env_parts < <(common_env_array)
    mapfile -d '' -t install_triplet < <(target_install_triplet "$target_id")

    cmd+=("${prefix[@]}")
    cmd+=("${memory_prefix[@]}")
    cmd+=("${env_parts[@]}")
    cmd+=(
        make
        -C
        "$BEAK_ROOT"
        "${install_triplet[0]}"
        "${install_triplet[1]}=${install_triplet[2]}"
    )
    printf '%s\0' "${cmd[@]}"
}

build_run_cmd() {
    local target_id="$1"
    local project_dir
    local -a cmd=()

    project_dir=$(target_project_dir "$target_id")
    mapfile -d '' -t prefix < <(cpu_prefix_array)
    mapfile -d '' -t memory_prefix < <(memory_prefix_array)
    mapfile -d '' -t env_parts < <(common_env_array)

    cmd+=("${prefix[@]}")
    cmd+=("${memory_prefix[@]}")
    cmd+=("${env_parts[@]}")
    case "$target_id" in
        sp1-3561f006)
            cmd+=(
                bash
                -lc
                'cd "$1" && CARGO_TARGET_DIR="$1/target" cargo run --release -q --bin beak-trace -- --json'
                _
                "$project_dir"
            )
            ;;
        sp1-fb38df2c)
            cmd+=(
                bash
                -lc
                'set -euo pipefail; cd "$1"; export CARGO_TARGET_DIR="$1/target"; for scenario in load jump bneinc; do cargo run --release -q --bin beak-trace -- --scenario "$scenario" --json; done'
                _
                "$project_dir"
            )
            ;;
        *)
            cmd+=(
                bash
                -lc
                'cd "$1" && CARGO_TARGET_DIR="$1/target" cargo run --release -q --bin beak-fuzz -- --seeds-jsonl "$2" --timeout-ms "$3" --initial-limit "$4" --max-instructions "$5" --oracle-precheck-max-steps "$6" --semantic-window-before "$7" --semantic-window-after "$8" --semantic-step-stride "$9" --semantic-max-trials-per-bucket "${10}"'
                _
                "$project_dir"
                "$SEEDS_JSONL"
                "$SEED_TIMEOUT_MS"
                "$INITIAL_LIMIT"
                "$MAX_INSTRUCTIONS"
                "$ORACLE_PRECHECK_MAX_STEPS"
                "$SEMANTIC_WINDOW_BEFORE"
                "$SEMANTIC_WINDOW_AFTER"
                "$SEMANTIC_STEP_STRIDE"
                "$SEMANTIC_MAX_TRIALS"
            )
            ;;
    esac
    printf '%s\0' "${cmd[@]}"
}

append_summary() {
    local target_id="$1"
    local commit="$2"
    local status="$3"
    local detail="$4"

    mkdir -p "$(dirname -- "$SUMMARY_PATH")"
    if [[ ! -f "$SUMMARY_PATH" ]]; then
        printf 'target\tcommit\tstatus\tdetail\n' >"$SUMMARY_PATH"
    fi
    printf '%s\t%s\t%s\t%s\n' "$target_id" "$commit" "$status" "$detail" >>"$SUMMARY_PATH"
}

run_target() {
    local target_id="$1"
    local commit
    local project_dir
    local install_log
    local run_log
    local rc

    commit=$(target_commit "$target_id")
    project_dir=$(target_project_dir "$target_id")
    install_log="$LOG_ROOT/install-$target_id.log"
    run_log="$LOG_ROOT/run-$target_id.log"

    echo "== [$target_id] start =="
    echo "   commit       : $commit"
    echo "   project_dir  : $project_dir"
    echo "   install_log  : $install_log"
    echo "   run_log      : $run_log"

    if [[ "$SKIP_INSTALL" -eq 0 ]]; then
        mapfile -d '' -t install_cmd < <(build_install_cmd "$target_id")
        if ! run_and_log "$install_log" "${install_cmd[@]}"; then
            append_summary "$target_id" "$commit" "install_failed" "$install_log"
            echo "== [$target_id] install failed =="
            return 1
        fi
    else
        echo "   skip install : true"
    fi

    mapfile -d '' -t run_cmd < <(build_run_cmd "$target_id")
    if run_with_reaper "$SOFT_TIMEOUT_SECONDS" "$KILL_GRACE_SECONDS" "$run_log" "${run_cmd[@]}"; then
        append_summary "$target_id" "$commit" "ok" "$run_log"
        echo "== [$target_id] completed before budget =="
        return 0
    else
        rc=$?
    fi

    if [[ "$rc" -eq 124 ]]; then
        append_summary "$target_id" "$commit" "budget_reached" "$run_log"
        echo "== [$target_id] 4h budget reached =="
        return 0
    fi

    append_summary "$target_id" "$commit" "run_failed" "$run_log"
    echo "== [$target_id] run failed with exit code $rc =="
    return "$rc"
}

print_target_commands() {
    local target_id="$1"
    mapfile -d '' -t install_cmd < <(build_install_cmd "$target_id")
    mapfile -d '' -t run_cmd < <(build_run_cmd "$target_id")
    echo "[$target_id] install"
    quote_cmd "${install_cmd[@]}"
    echo "[$target_id] run"
    quote_cmd "${run_cmd[@]}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-commands)
            PRINT_COMMANDS=1
            shift
            ;;
        --skip-install)
            SKIP_INSTALL=1
            shift
            ;;
        --only-commit)
            [[ $# -ge 2 ]] || { echo "--only-commit requires a value" >&2; exit 1; }
            ONLY_COMMITS+=("$2")
            shift 2
            ;;
        --exclude-commit)
            [[ $# -ge 2 ]] || { echo "--exclude-commit requires a value" >&2; exit 1; }
            EXCLUDE_COMMITS+=("$2")
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_cmd bash
require_cmd cargo
require_cmd make
require_cmd tee
require_cmd setsid
require_cmd prlimit
if [[ "$SKIP_INSTALL" -eq 0 ]]; then
    require_cmd uv
fi

if [[ ! -f "$SEEDS_JSONL" ]]; then
    echo "seed file not found: $SEEDS_JSONL" >&2
    exit 1
fi

mapfile -t ALL_TARGETS < <(target_ids)
FILTERED_TARGETS=()
for target_id in "${ALL_TARGETS[@]}"; do
    commit=$(target_commit "$target_id")
    if matches_filters "$target_id" "$commit"; then
        FILTERED_TARGETS+=("$target_id")
    fi
done

echo "Beak serial install+injection"
echo "  targets         : ${#FILTERED_TARGETS[@]}"
echo "  threads         : $THREADS"
echo "  cpu_set         : $CPU_SET"
echo "  timeout_s       : $SOFT_TIMEOUT_SECONDS"
echo "  grace_s         : $KILL_GRACE_SECONDS"
echo "  seed_timeout_ms : $SEED_TIMEOUT_MS"
echo "  initial_limit   : $INITIAL_LIMIT"
echo "  max_instructions: $MAX_INSTRUCTIONS"
echo "  oracle_precheck : $ORACLE_PRECHECK_MAX_STEPS"
echo "  sem_before      : $SEMANTIC_WINDOW_BEFORE"
echo "  sem_after       : $SEMANTIC_WINDOW_AFTER"
echo "  sem_stride      : $SEMANTIC_STEP_STRIDE"
echo "  sem_max_trials  : $SEMANTIC_MAX_TRIALS"
echo "  fast_test       : $FAST_TEST"
echo "  seeds_jsonl     : $SEEDS_JSONL"
echo "  mem_limit       : ${MEMORY_LIMIT_GB}G ($MEMORY_LIMIT_BYTES bytes)"
echo "  run_root        : $RUN_ROOT"

if [[ "$PRINT_COMMANDS" -eq 1 ]]; then
    for target_id in "${FILTERED_TARGETS[@]}"; do
        print_target_commands "$target_id"
    done
    exit 0
fi

mkdir -p "$(dirname -- "$SUMMARY_PATH")"
printf 'target\tcommit\tstatus\tdetail\n' >"$SUMMARY_PATH"

overall_rc=0
for target_id in "${FILTERED_TARGETS[@]}"; do
    if ! run_target "$target_id"; then
        overall_rc=1
    fi
done

echo "Summary written to $SUMMARY_PATH"
exit "$overall_rc"
