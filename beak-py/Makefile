# ---------------------------------------------------------------------------- #
#                                 Project Files                                #
# ---------------------------------------------------------------------------- #

ROOT=$(shell pwd)
VIRTUALENV=$(ROOT)/.venv
export UV_CACHE_DIR ?= $(ROOT)/.uv-cache
SP1_COMMIT ?= 39ab52fce38172c9d23feed7248198dc14c164a9
RISC0_COMMIT ?= c0db0713671c8ec467b3efc26b22a0b0591897ff
RISC0_ZKVM_SRC ?= ./risc0-src
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
	$(UV_RUN) sp1-fuzzer install --commit-or-branch $(SP1_COMMIT)

install-risc0: $(VIRTUALENV)
	uv sync --package risc0-fuzzer
	$(UV_RUN) risc0-fuzzer install --zkvm-src $(RISC0_ZKVM_SRC) --commit-or-branch $(RISC0_COMMIT)

install-pico: $(VIRTUALENV)
	uv sync --package pico-fuzzer
	$(UV_RUN) pico-fuzzer install --commit-or-branch dd5b7d1f4e164d289d110f1688509a22af6b241c

install-jolt: $(VIRTUALENV)
	uv sync --package jolt-fuzzer
	$(UV_RUN) jolt-fuzzer install --zkvm-src ./jolt-src --commit-or-branch e9caa23565dbb13019afe61a2c95f51d1999e286

install-nexus: $(VIRTUALENV)
	uv sync --package nexus-fuzzer
	$(UV_RUN) nexus-fuzzer install --zkvm-src ./nexus-src --commit-or-branch 636ccb360d0f4ae657ae4bb64e1e275ccec8826

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
