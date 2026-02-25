.PHONY: extract-initial-seeds openvm-install openvm-build openvm-run openvm-example-x0 \
	openvm-fuzz-build openvm-fuzz openvm-fuzz-5min openvm-fuzz-quick \
	openvm-trace openvm-trace-buckets

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
BIN ?= beak-trace
ARGS ?=

OPENVM_PYTHONPATH := beak-py/projects/openvm-fuzzer
PYTHON ?= python3

# Loop1 (beak-fuzz) default parameters
SEEDS_JSONL ?= storage/fuzzing_seeds/initial.jsonl
TIMEOUT_MS ?= 2000
INITIAL_LIMIT ?= 1
MAX_INSTRUCTIONS ?= 32
ITERS ?= 500
FAST_TEST ?= 1
NO_INITIAL_EVAL ?= 1

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

# --- Loop1 fuzzing (beak-fuzz) ---
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
	echo "Running loop1 in $${proj} (iters=$(ITERS), initial_limit=$(INITIAL_LIMIT), no_initial_eval=$(NO_INITIAL_EVAL))" && \
	cd "$${proj}" && FAST_TEST="$(FAST_TEST)" cargo run --release -q --bin beak-fuzz -- \
		--seeds-jsonl "$(SEEDS_JSONL)" \
		--timeout-ms "$(TIMEOUT_MS)" \
		--initial-limit "$(INITIAL_LIMIT)" \
		--max-instructions "$(MAX_INSTRUCTIONS)" \
		$(if $(filter 1 true yes,$(NO_INITIAL_EVAL)),--no-initial-eval,) \
		--iters "$(ITERS)"
