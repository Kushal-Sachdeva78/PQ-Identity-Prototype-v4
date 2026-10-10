# Publication code: validation is separate from timed measurement campaigns.
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
PYTHON ?= python3

.PHONY: all help install validate full build test pins manifest lint security \
        bench-inputs bench-analyze cmp-analyze e2e-analyze robustness-smoke docker

all: validate

help:
	@echo "make validate   locked install, artifact integrity, typecheck, selected tests"
	@echo "make full       validation plus environment, recompile, key audit, security suite"
	@echo "make build      TypeScript typecheck (run make install first)"
	@echo "make pins       verify both committed setup pin files"
	@echo "make manifest   verify setup pins and the publication manifest"
	@echo "make docker     build and run full validation in the pinned Linux environment"
	@echo "See REPRODUCE.md for experiment dependencies and campaign commands."

install:
	npm ci --no-audit --no-fund

validate:
	bash artifact/rebuild.sh

full:
	bash artifact/rebuild.sh --full

build:
	npx tsc -p tsconfig.json --noEmit

test:
	npx vitest run tests/v4
	npx vitest run tests/circuit.test.ts tests/determinism.test.ts tests/circuit_v3.test.ts

pins:
	$(PYTHON) scripts/verify_artifacts.py

manifest:
	$(PYTHON) scripts/verify_artifacts.py --manifest

lint:
	npm run lint

security:
	bash artifact/rebuild.sh --full --no-install

bench-inputs:
	npx tsx harness/v4/bench/inputs.ts --check

bench-analyze:
	$(PYTHON) scripts/bench/analyze.py

cmp-analyze:
	$(PYTHON) scripts/cmp/analyze_cmp.py

e2e-analyze:
	$(PYTHON) scripts/e2e/analyze_e2e.py

robustness-smoke:
	bash scripts/robustness/run_robustness.sh smoke

docker:
	docker build -f artifact/Dockerfile -t pqid-publication .
	docker run --rm pqid-publication bash artifact/rebuild.sh --full --no-install
