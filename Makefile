.PHONY: setup lint format test ci clean zip

setup:
	pip install -r requirements.txt

lint:
	ruff check .

format:
	ruff format .

test:
	pytest -v

ci: lint test

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info

zip:
	zip -r ../adversary-emulation-framework.zip . -x ".git/*" "__pycache__/*" ".pytest_cache/*" ".mypy_cache/*" ".ruff_cache/*"
