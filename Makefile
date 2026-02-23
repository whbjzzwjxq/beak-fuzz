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
COMMIT ?=
BIN ?= beak-trace
ARGS ?=

OPENVM_PYTHONPATH := beak-py/projects/openvm-fuzzer
PYTHON ?= python3

# Loop1 (beak-fuzz) parameters
SEEDS_JSONL ?= storage/fuzzing_seeds/initial.jsonl
TIMEOUT_MS ?= 2000
INITIAL_LIMIT ?= 0
MAX_INSTRUCTIONS ?= 256
ITERS ?= 100
RUN_SECS ?= 300

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
	python scripts/extract_initial_seeds.py \
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

# --- Loop1 fuzzing (beak-fuzz) ---
openvm-fuzz-build:
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Building $${proj} (BIN=beak-fuzz)" && \
	cd "$${proj}" && CARGO_TARGET_DIR="$$PWD/target" cargo build --bin beak-fuzz

openvm-fuzz: openvm-fuzz-build
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Running loop1 in $${proj} (iters=$(ITERS), initial_limit=$(INITIAL_LIMIT))" && \
	cd "$${proj}" && ./target/debug/beak-fuzz \
		--seeds-jsonl "$(SEEDS_JSONL)" \
		--timeout-ms "$(TIMEOUT_MS)" \
		--initial-limit "$(INITIAL_LIMIT)" \
		--max-instructions "$(MAX_INSTRUCTIONS)" \
		--iters "$(ITERS)"

# Run loop1 for ~RUN_SECS seconds, then SIGTERM.
openvm-fuzz-5min: openvm-fuzz-build
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Running loop1 for ~$(RUN_SECS)s in $${proj}" && \
	cd "$${proj}" && sh -c '\
		./target/debug/beak-fuzz \
			--seeds-jsonl $(SEEDS_JSONL) \
			--timeout-ms $(TIMEOUT_MS) \
			--initial-limit $(INITIAL_LIMIT) \
			--max-instructions $(MAX_INSTRUCTIONS) \
			--iters $(ITERS) \
			& pid=$$!; \
		sleep $(RUN_SECS); \
		kill -TERM $$pid 2>/dev/null || true; \
		sleep 5; \
		kill -KILL $$pid 2>/dev/null || true; \
		wait $$pid || true \
	'

# Quick smoke: one AUIPC seed that writes x0.
openvm-fuzz-quick: openvm-fuzz-build
	$(_require_commit)
	@resolved="$$( $(_openvm_resolve) )" && \
	proj="projects/openvm-$${resolved}" && \
	echo "Running quick loop1 smoke in $${proj}" && \
	cd "$${proj}" && ./target/debug/beak-fuzz \
		--seeds-jsonl storage/fuzzing_seeds/quick-auipc-x0.jsonl \
		--timeout-ms 2000 \
		--initial-limit 1 \
		--no-initial-eval \
		--max-instructions 16 \
		--iters 0

# Convenience: trace CLI (beak-trace)
openvm-trace:
	@$(MAKE) openvm-run BIN=beak-trace ARGS='--bin "$(WORDS)"'

openvm-trace-buckets:
	@$(MAKE) openvm-run BIN=beak-trace ARGS='--print-buckets --bin "$(WORDS)"'

# Example: run a seed that writes x0 (should detect mismatch).
# Prereq: install the OpenVM snapshot first:
#   make openvm-install COMMIT=bmk-regzero
openvm-example-x0:
	@$(MAKE) openvm-run COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "12345017 00000533"'
