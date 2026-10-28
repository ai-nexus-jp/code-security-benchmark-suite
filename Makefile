PYTHON := $(shell which python3)
PYTEST := $(shell which pytest)

# Use virtual environment binaries if present
ifneq ("$(wildcard .venv/bin/python3)","")
    PYTHON := .venv/bin/python3
    PYTEST := .venv/bin/pytest
endif

.PHONY: setup test-app run-benchmark clean help

help:
	@echo "Available commands:"
	@echo "  make setup          Install dependencies into environment"
	@echo "  make test-app       Run test suite on bench_app"
	@echo "  make run-benchmark  Execute all 4 scanner benchmarks and generate reports"
	@echo "  make clean          Remove generated reports and temporary raw outputs"

setup:
	$(PYTHON) -m pip install -r requirements.txt

test-app:
	$(PYTEST) bench_app/tests

run-benchmark:
	$(PYTHON) runner/scanners/bandit_runner.py
	$(PYTHON) runner/scanners/semgrep_runner.py
	$(PYTHON) runner/scanners/raw_llm_runner.py
	$(PYTHON) runner/scanners/mantis_runner.py
	$(PYTHON) runner/evaluate.py

clean:
	rm -f materials/*.json materials/*.csv materials/*.md

