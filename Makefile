.PHONY: extract-initial-seeds openvm-install openvm-build openvm-run openvm-example-x0 \
	openvm-fuzz-build openvm-fuzz openvm-fuzz-5min openvm-fuzz-quick \
	openvm-trace openvm-trace-buckets \
	pico-install pico-build pico-run pico-fuzz \
	sp1-install sp1-build sp1-run sp1-fuzz \
	jolt-install jolt-build jolt-run jolt-fuzz \
	nexus-install nexus-build nexus-run nexus-fuzz

# Commit selector (required for OpenVM targets).
#
# Usage examples:
#   make openvm-install COMMIT=bmk-regzero
#   make openvm-build COMMIT=bmk-regzero BIN=beak-trace
#   make openvm-run   COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "12345017 00000533"'
#
# COMMIT can be a full SHA or an alias defined in:
#   beak-py/projects/openvm-fuzzer/openvm_fuzzer/settings.py
COMMIT ?= bmk-regzero
PICO_COMMIT ?= 45e74ccd62758c6d67239913956e749adaba261c
SP1_COMMIT ?= 7f643da16813af4c0fbaad4837cd7409386cf38c
JOLT_COMMIT ?= e9caa23565dbb13019afe61a2c95f51d1999e286
NEXUS_COMMIT ?= 636ccb360d0f4ae657ae4bb64e1e275ccec8826
BIN ?= beak-trace
ARGS ?=

OPENVM_PYTHONPATH := beak-py/projects/openvm-fuzzer
PYTHON ?= python3

# Benchmark (beak-fuzz) default parameters
SEEDS_JSONL ?= storage/fuzzing_seeds/initial.jsonl
TIMEOUT_MS ?= 500
INITIAL_LIMIT ?= 500
MAX_INSTRUCTIONS ?= 32
SEMANTIC_WINDOW_BEFORE ?= 16
SEMANTIC_WINDOW_AFTER ?= 64
SEMANTIC_STEP_STRIDE ?= 1
SEMANTIC_MAX_TRIALS ?= 64
FAST_TEST ?= 1

# Pico (OpenVM-style project entry)
PICO_PROJECT_DIR ?= projects/pico-$(PICO_COMMIT)
PICO_ZKVM_DIR ?= $(abspath beak-py/out/pico-$(PICO_COMMIT)/pico-src)
PICO_OUT_DIR ?= $(abspath $(PICO_PROJECT_DIR)/out)
PICO_SEEDS ?= storage/fuzzing_seeds/initial.jsonl
PICO_INITIAL_LIMIT ?= 1000
PICO_ARGS ?=

# SP1 (OpenVM-style project entry)
SP1_PROJECT_DIR ?= projects/sp1-$(SP1_COMMIT)
SP1_ZKVM_DIR ?= $(abspath beak-py/out/sp1-$(SP1_COMMIT)/sp1-src)
SP1_OUT_DIR ?= $(abspath $(SP1_PROJECT_DIR)/out)
SP1_SEEDS ?= storage/fuzzing_seeds/initial.jsonl
SP1_INITIAL_LIMIT ?= 1000
SP1_ARGS ?=

# Jolt
JOLT_PROJECT_DIR ?= projects/jolt-$(JOLT_COMMIT)
JOLT_ZKVM_DIR ?= $(abspath beak-py/out/jolt-$(JOLT_COMMIT)/jolt-src)
JOLT_OUT_DIR ?= $(abspath $(JOLT_PROJECT_DIR)/out)
JOLT_SEEDS ?= storage/fuzzing_seeds/initial.jsonl
JOLT_INITIAL_LIMIT ?= 1000
JOLT_TIMEOUT_MS ?= 10000
JOLT_ARGS ?=

# Nexus
NEXUS_PROJECT_DIR ?= projects/nexus-$(NEXUS_COMMIT)
NEXUS_ZKVM_DIR ?= $(abspath beak-py/out/nexus-$(NEXUS_COMMIT)/nexus-src)
NEXUS_OUT_DIR ?= $(abspath $(NEXUS_PROJECT_DIR)/out)
NEXUS_SEEDS ?= storage/fuzzing_seeds/initial.jsonl
NEXUS_INITIAL_LIMIT ?= 1000
NEXUS_TIMEOUT_MS ?= 5000
NEXUS_ARGS ?=

define _require_pico_commit
	@if [ -z "$(PICO_COMMIT)" ]; then \
		echo "error: PICO_COMMIT is required (full SHA, e.g. 45e74ccd...)"; \
		exit 2; \
	fi
endef

define _require_sp1_commit
	@if [ -z "$(SP1_COMMIT)" ]; then \
		echo "error: SP1_COMMIT is required (full SHA, e.g. 7f643da...)"; \
		exit 2; \
	fi
endef

define _require_jolt_commit
	@if [ -z "$(JOLT_COMMIT)" ]; then \
		echo "error: JOLT_COMMIT is required (full SHA, e.g. e9caa235...)"; \
		exit 2; \
	fi
endef

define _require_nexus_commit
	@if [ -z "$(NEXUS_COMMIT)" ]; then \
		echo "error: NEXUS_COMMIT is required (full SHA, e.g. 636ccb36...)"; \
		exit 2; \
	fi
endef

define _require_commit
	@if [ -z "$(COMMIT)" ]; then \
		echo "error: COMMIT is required (full SHA or alias, e.g. bmk-regzero)"; \
		exit 2; \
	fi
endef

define _openvm_resolve
PYTHONPATH="$(OPENVM_PYTHONPATH)" $(PYTHON) -c 'import sys; arg=sys.argv[1]; exec("""\ntry:\n  from openvm_fuzzer.settings import resolve_openvm_commit\n  print(resolve_openvm_commit(arg))\nexcept Exception:\n  import re\n  if re.fullmatch(r\"[0-9a-f]{40}\", arg):\n    print(arg)\n  else:\n    raise\n""")' "$(COMMIT)"
endef

extract-initial-seeds:
	@mkdir -p storage/fuzzing_seeds
	$(PYTHON) scripts/extract_initial_seeds.py \
		-i storage/riscv-tests-artifacts \
		-o storage/fuzzing_seeds/initial.jsonl

openvm-install:
	$(_require_commit)
	cd beak-py && make install
	cd beak-py && uv run openvm-fuzzer install --commit-or-branch "$(COMMIT)"

openvm-build:
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Building $${proj} (BIN=$(BIN))" && \
	cd "$${proj}" && CARGO_TARGET_DIR="$$PWD/target" cargo build --bin "$(BIN)"

openvm-run:
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Running $${proj} (BIN=$(BIN))" && \
	cd "$${proj}" && CARGO_TARGET_DIR="$$PWD/target" cargo run --bin "$(BIN)" -- $(ARGS)

openvm-example-x0:
	@$(MAKE) openvm-run COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "12345017 00000533"'

# --- Benchmark fuzzing (beak-fuzz) ---
openvm-fuzz-build:
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Building $${proj} (BIN=beak-fuzz, profile=release)" && \
	cd "$${proj}" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-fuzz

openvm-fuzz: openvm-fuzz-build
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Running benchmark in $${proj} (initial_limit=$(INITIAL_LIMIT), semantic_max_trials=$(SEMANTIC_MAX_TRIALS))" && \
	cd "$${proj}" && FAST_TEST="$(FAST_TEST)" cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(SEEDS_JSONL)" \
		--timeout-ms "$(TIMEOUT_MS)" \
		--initial-limit "$(INITIAL_LIMIT)" \
		--max-instructions "$(MAX_INSTRUCTIONS)" \
		--semantic-window-before "$(SEMANTIC_WINDOW_BEFORE)" \
		--semantic-window-after "$(SEMANTIC_WINDOW_AFTER)" \
		--semantic-step-stride "$(SEMANTIC_STEP_STRIDE)" \
		--semantic-max-trials-per-bucket "$(SEMANTIC_MAX_TRIALS)"

pico-install:
	$(_require_pico_commit)
	@mkdir -p "$(PICO_PROJECT_DIR)"
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} make install
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} uv run pico-fuzzer install --commit-or-branch "$(PICO_COMMIT)"

pico-build:
	$(_require_pico_commit)
	@mkdir -p "$(PICO_PROJECT_DIR)"
	cd "$(PICO_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-trace --bin beak-fuzz

pico-run: pico-build
	$(_require_pico_commit)
	@mkdir -p "$(PICO_OUT_DIR)"
	cd "$(PICO_PROJECT_DIR)" && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(PICO_SEEDS)" \
		--initial-limit "$(PICO_INITIAL_LIMIT)" \
		--semantic-window-before "$(SEMANTIC_WINDOW_BEFORE)" \
		--semantic-window-after "$(SEMANTIC_WINDOW_AFTER)" \
		--semantic-step-stride "$(SEMANTIC_STEP_STRIDE)" \
		--semantic-max-trials-per-bucket "$(SEMANTIC_MAX_TRIALS)" \
		$(PICO_ARGS)

# OpenVM-like single entry: project-local beak-fuzz workflow
pico-fuzz: pico-run
	@echo "Pico full repro finished for $(PICO_COMMIT)"

sp1-install:
	$(_require_sp1_commit)
	@mkdir -p "$(SP1_PROJECT_DIR)"
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} make install
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} uv run sp1-fuzzer install --commit-or-branch "$(SP1_COMMIT)"

sp1-build:
	$(_require_sp1_commit)
	@mkdir -p "$(SP1_PROJECT_DIR)"
	cd "$(SP1_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-trace --bin beak-fuzz

sp1-run: sp1-build
	$(_require_sp1_commit)
	@mkdir -p "$(SP1_OUT_DIR)"
	cd "$(SP1_PROJECT_DIR)" && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(SP1_SEEDS)" \
		--initial-limit "$(SP1_INITIAL_LIMIT)" \
		--semantic-window-before "$(SEMANTIC_WINDOW_BEFORE)" \
		--semantic-window-after "$(SEMANTIC_WINDOW_AFTER)" \
		--semantic-step-stride "$(SEMANTIC_STEP_STRIDE)" \
		--semantic-max-trials-per-bucket "$(SEMANTIC_MAX_TRIALS)" \
		$(SP1_ARGS)

# OpenVM-like single entry: project-local beak-fuzz workflow
sp1-fuzz: sp1-run
	@echo "SP1 full repro finished for $(SP1_COMMIT)"

jolt-install:
	$(_require_jolt_commit)
	@mkdir -p "$(JOLT_PROJECT_DIR)"
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} make install
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} uv run jolt-fuzzer install --commit-or-branch "$(JOLT_COMMIT)"

jolt-build:
	$(_require_jolt_commit)
	@mkdir -p "$(JOLT_PROJECT_DIR)"
	cd "$(JOLT_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-trace --bin beak-fuzz

jolt-run: jolt-build
	$(_require_jolt_commit)
	@mkdir -p "$(JOLT_OUT_DIR)"
	cd "$(JOLT_PROJECT_DIR)" && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(JOLT_SEEDS)" \
		--timeout-ms "$(JOLT_TIMEOUT_MS)" \
		--initial-limit "$(JOLT_INITIAL_LIMIT)" \
		--semantic-window-before "$(SEMANTIC_WINDOW_BEFORE)" \
		--semantic-window-after "$(SEMANTIC_WINDOW_AFTER)" \
		--semantic-step-stride "$(SEMANTIC_STEP_STRIDE)" \
		--semantic-max-trials-per-bucket "$(SEMANTIC_MAX_TRIALS)" \
		$(JOLT_ARGS)

jolt-fuzz: jolt-run
	@echo "Jolt full repro finished for $(JOLT_COMMIT)"

# --- RL Fuzzing targets ---
RL_POLICY ?= bandit
RL_ITERS ?= 1000
RL_METRICS_INTERVAL ?= 10
RL_SOCKET ?= /tmp/beak-rl.sock

jolt-rl-build:
	$(_require_jolt_commit)
	@mkdir -p "$(JOLT_PROJECT_DIR)"
	cd "$(JOLT_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-fuzz-rl

jolt-rl-run: jolt-rl-build
	$(_require_jolt_commit)
	@mkdir -p "$(JOLT_OUT_DIR)"
	cd "$(JOLT_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo run --release -q --bin beak-fuzz-rl -- \
		--policy "$(RL_POLICY)" \
		--iters "$(RL_ITERS)" \
		--metrics-interval "$(RL_METRICS_INTERVAL)" \
		--seeds-jsonl "$(JOLT_SEEDS)" \
		--timeout-ms "$(JOLT_TIMEOUT_MS)" \
		--initial-limit "$(JOLT_INITIAL_LIMIT)" \
		$(JOLT_ARGS)

jolt-rl-bandit:
	$(MAKE) jolt-rl-run RL_POLICY=bandit

jolt-rl-linucb:
	$(MAKE) jolt-rl-run RL_POLICY=linucb

jolt-rl-external:
	./scripts/run_with_rl.sh --iters "$(RL_ITERS)" --metrics-interval "$(RL_METRICS_INTERVAL)" \
		--seeds-jsonl "$(JOLT_SEEDS)" --timeout-ms "$(JOLT_TIMEOUT_MS)" --initial-limit "$(JOLT_INITIAL_LIMIT)"

jolt-rl-compare:
	@echo "=== Running Bandit baseline ==="
	$(MAKE) jolt-rl-run RL_POLICY=bandit JOLT_ARGS="--output-prefix bandit-run1"
	@echo "=== Running LinUCB ==="
	$(MAKE) jolt-rl-run RL_POLICY=linucb JOLT_ARGS="--output-prefix linucb-run1"
	@echo "=== Generating comparison plots ==="
	PYTHONPATH=beak-py python3 -m rl.visualize --metrics-dir storage/fuzzing_seeds --output-dir output/figures

nexus-install:
	$(_require_nexus_commit)
	@mkdir -p "$(NEXUS_PROJECT_DIR)"
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} make install
	cd beak-py && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} uv run nexus-fuzzer install --commit-or-branch "$(NEXUS_COMMIT)"

nexus-build:
	$(_require_nexus_commit)
	@mkdir -p "$(NEXUS_PROJECT_DIR)"
	cd "$(NEXUS_PROJECT_DIR)" && CARGO_TARGET_DIR="$$PWD/target" cargo build --release --bin beak-trace --bin beak-fuzz

nexus-run: nexus-build
	$(_require_nexus_commit)
	@mkdir -p "$(NEXUS_OUT_DIR)"
	cd "$(NEXUS_PROJECT_DIR)" && UV_CACHE_DIR=$${UV_CACHE_DIR:-/tmp/uv-cache} cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(NEXUS_SEEDS)" \
		--timeout-ms "$(NEXUS_TIMEOUT_MS)" \
		--initial-limit "$(NEXUS_INITIAL_LIMIT)" \
		--semantic-window-before "$(SEMANTIC_WINDOW_BEFORE)" \
		--semantic-window-after "$(SEMANTIC_WINDOW_AFTER)" \
		--semantic-step-stride "$(SEMANTIC_STEP_STRIDE)" \
		--semantic-max-trials-per-bucket "$(SEMANTIC_MAX_TRIALS)" \
		$(NEXUS_ARGS)

nexus-fuzz: nexus-run
	@echo "Nexus full repro finished for $(NEXUS_COMMIT)"
