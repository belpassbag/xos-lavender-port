.PHONY: check test

check: test
	python3 -m compileall -q tools tests
	python3 tools/portctl.py check
	python3 tools/compatctl.py check >/dev/null
	python3 tools/buildctl.py check >/dev/null
	python3 -c 'import json; json.load(open("docs/CASE-4-EVIDENCE.json", encoding="utf-8"))'
	! grep -R -E --exclude-dir=.git -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' .
	bash -n scripts/download-drive-file.sh
	bash -n scripts/download-drive-parts.sh
	bash -n scripts/extract-case3-selection.sh
	bash -n scripts/extract-case4-roots.sh
	bash -n scripts/materialize-case4-images.sh
	bash -n scripts/prepare-parts.sh

test:
	python3 -m unittest discover -s tests -v
