venv=.venv
python=$(venv)/bin/python

default: help

.PHONY: help
help:
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

.PHONY: lint
.SILENT: lint
lint: # Run the linter
	mypy riot_auth
	ruff check riot_auth
	ruff format riot_auth --check

.PHONY: format
.SILENT: format
format: # Format the code
	ruff check riot_auth --fix
	ruff format riot_auth
