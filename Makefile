.PHONY: install lint security test check sample scan scan-gcp breach breach-baseline clean

install:
	pip install -r requirements-dev.txt

lint:
	ruff check .

security:
	bandit -q -r scanner breachlab

test:
	python -m pytest -q

check: lint security test

sample:
	PYTHONPATH=. python examples/generate_sample.py
	PYTHONPATH=. python examples/generate_sample_gcp.py

scan-gcp:
	python -m scanner --provider gcp --project $(PROJECT) --output reports

scan:
	python -m scanner --regions us-east-1 --output reports

breach:
	python -m breachlab run --report reports/incident-report.md

breach-baseline:
	python -m breachlab baseline

clean:
	rm -rf reports .pytest_cache .ruff_cache **/__pycache__
