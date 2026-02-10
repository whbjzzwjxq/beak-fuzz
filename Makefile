extract-initial-seeds:
	@mkdir -p storage/fuzzing_seeds
	python scripts/extract_initial_seeds.py \
		-i storage/riscv-tests-artifacts \
		-o storage/fuzzing_seeds/initial.jsonl
