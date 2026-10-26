# WhyWard developer entry points. Everything here works with the standard
# library plus the dev extras in pyproject.toml.
PYTHON ?= python3
VENV ?= .venv

.PHONY: help test lint type security coverage probes verify acceptance clean

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/ — /'

test: ## run the stdlib test suite
	PYTHONPATH=src:tests $(PYTHON) -m unittest discover -s tests -t tests

lint: ## ruff
	ruff check src tests

type: ## mypy strict on the package
	mypy

security: ## bandit, medium severity and above
	bandit -q -r src -ll

coverage: ## branch coverage gate (85%)
	coverage run --source=src/whyward -m pytest -q
	coverage report

probes: ## 15 adversarial security probes
	PYTHONPATH=src $(PYTHON) docs/audit/reproduce_findings.py

verify: lint type security coverage probes test ## everything CI runs

acceptance: ## clean-room acceptance harness (needs a clean git tree)
	$(PYTHON) docs/acceptance/acceptance_runner.py --report /tmp/acceptance-report.md

clean:
	rm -rf .whyward-demo .coverage htmlcov .mypy_cache .ruff_cache
