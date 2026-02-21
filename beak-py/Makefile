# ---------------------------------------------------------------------------- #
#                                 Project Files                                #
# ---------------------------------------------------------------------------- #

ROOT=$(shell pwd)
VIRTUALENV=$(ROOT)/.venv
export UV_CACHE_DIR ?= $(ROOT)/.uv-cache
UV_RUN=uv run
BLACK=$(UV_RUN) black
FLAKE8=$(UV_RUN) flake8
ISORT=$(UV_RUN) isort
PYRIGHT=$(UV_RUN) pyright
PYTEST=$(UV_RUN) pytest
PYRIGHTCONFIG=$(ROOT)/pyrightconfig.json

# ---------------------------------------------------------------------------- #
#                                Command Section                               #
# ---------------------------------------------------------------------------- #

.PHONY: check clean format install ship test venv install-openvm install-sp1 install-risc0 install-pico install-jolt install-nexus

$(VIRTUALENV):
	uv venv

venv: $(VIRTUALENV)

clean:
	rm -rf $(VIRTUALENV) $(PYRIGHTCONFIG) uv.lock
	find . -type d -name "__pycache__" -exec rm -rf {} +

install: $(VIRTUALENV)
	uv sync

install-openvm: $(VIRTUALENV)
	uv sync --package openvm-fuzzer
	$(UV_RUN) openvm-fuzzer install

install-sp1: $(VIRTUALENV)
	uv sync --package sp1-fuzzer
	$(UV_RUN) sp1-fuzzer install --zkvm-src ./sp1-src --commit-or-branch 7f643da16813af4c0fbaad4837cd7409386cf38c --inject

install-risc0: $(VIRTUALENV)
	uv sync --package risc0-fuzzer
	$(UV_RUN) risc0-fuzzer install --zkvm-src ./risc0-src --commit-or-branch ebd64e43e7d953e0edcee2d4e0225b75458d80b5

install-pico: $(VIRTUALENV)
	uv sync --package pico-fuzzer
	$(UV_RUN) pico-fuzzer install --zkvm-src ./pico-src --commit-or-branch dd5b7d1f4e164d289d110f1688509a22af6b241c

install-jolt: $(VIRTUALENV)
	uv sync --package jolt-fuzzer
	$(UV_RUN) jolt-fuzzer install --zkvm-src ./jolt-src --commit-or-branch main

install-nexus: $(VIRTUALENV)
	uv sync --package nexus-fuzzer
	$(UV_RUN) nexus-fuzzer install --zkvm-src ./nexus-src --commit-or-branch main

$(PYRIGHTCONFIG):
	@echo "Generating $(PYRIGHTCONFIG) for pyright ..."
	echo '{'                                  >  $(PYRIGHTCONFIG)
	echo '    "extraPaths" : ['               >> $(PYRIGHTCONFIG)
	echo '        "./libs/zkvm-fuzzer-utils",' >> $(PYRIGHTCONFIG)
	echo '        "./projects/openvm-fuzzer",' >> $(PYRIGHTCONFIG)
	echo '        "./projects/sp1-fuzzer",'   >> $(PYRIGHTCONFIG)
	echo '        "./projects/risc0-fuzzer",' >> $(PYRIGHTCONFIG)
	echo '        "./projects/pico-fuzzer",'  >> $(PYRIGHTCONFIG)
	echo '        "./projects/jolt-fuzzer",'  >> $(PYRIGHTCONFIG)
	echo '        "./projects/nexus-fuzzer"'  >> $(PYRIGHTCONFIG)
	echo '    ]'                              >> $(PYRIGHTCONFIG)
	echo '}'                                  >> $(PYRIGHTCONFIG)

ship: format check test

check: $(PYRIGHTCONFIG)
	$(BLACK) --check .
	$(FLAKE8) .
	$(ISORT) --check-only .
	$(PYRIGHT) .

format:
	$(BLACK) .
	$(ISORT) .

test:
	FUZZER_TEST=1 $(PYTEST) -v

kill-all-fuzzer:
	killall python3 -9; killall cargo -9
