.PHONY: install lint security test check sample scan clean

install:
	pip install -r requirements-dev.txt

lint:
	ruff check .

security:
	bandit -q -r scanner

test:
	python -m pytest -q

check: lint security test

sample:
	PYTHONPATH=. python examples/generate_sample.py

scan:
	python -m scanner --regions us-east-1 --output reports

clean:
	rm -rf reports .pytest_cache .ruff_cache **/__pycache__
