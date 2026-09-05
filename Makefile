.PHONY: check test

check: test
	python3 tools/portctl.py check
	bash -n scripts/prepare-parts.sh

test:
	python3 -m unittest discover -s tests -v

