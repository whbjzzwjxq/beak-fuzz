.PHONY: extract-initial-seeds openvm-example-x0

extract-initial-seeds:
	@mkdir -p storage/fuzzing_seeds
	python scripts/extract_initial_seeds.py \
		-i storage/riscv-tests-artifacts \
		-o storage/fuzzing_seeds/initial.jsonl

# Example: run a seed that writes x0 (should detect mismatch).
# Prereq: install the OpenVM snapshot first:
#   cd beak-py && make install && uv run openvm-fuzzer install --commit-or-branch bmk-regzero
openvm-example-x0:
	cd projects/openvm && cargo run --bin beak-trace -- --bin "12345017 00000533"
