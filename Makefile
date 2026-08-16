# Athena Agents - Unified Build System
# Requires: Rust toolchain (cargo), Python 3.11+

SHELL := /bin/bash
.DEFAULT_GOAL := build

# Configurable binary output directory (Requirement 13.4)
ATHENA_BIN_DIR ?= ./target/release

# Dependency checks
.PHONY: check-rust check-python

check-rust:
	@command -v cargo >/dev/null 2>&1 || { \
		echo "ERROR: Rust toolchain not found. Install from https://rustup.rs/" >&2; \
		exit 1; \
	}

check-python:
	@command -v python3 >/dev/null 2>&1 || { \
		echo "ERROR: Python 3 not found. Install Python 3.11+ from https://python.org/" >&2; \
		exit 1; \
	}

##@ Build

.PHONY: build
build: check-rust check-python ## Compile Rust crates + install Python deps
	@if cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['workspace_members'] else 1)" 2>/dev/null; then \
		cargo build --release || exit 1; \
	else \
		echo "NOTE: No Rust crates in workspace yet; skipping cargo build."; \
	fi
	python3 -m pip install --quiet -e ".[dev]"

##@ Testing

.PHONY: test
test: check-rust check-python ## Run cargo test + pytest
	@if cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['workspace_members'] else 1)" 2>/dev/null; then \
		cargo test || exit 1; \
	else \
		echo "NOTE: No Rust crates in workspace yet; skipping cargo test."; \
	fi
	python3 -m pytest

##@ Code Quality

.PHONY: lint
lint: check-rust check-python ## Run cargo clippy + ruff
	@if cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['workspace_members'] else 1)" 2>/dev/null; then \
		cargo clippy --all-targets --all-features -- -D warnings || exit 1; \
	else \
		echo "NOTE: No Rust crates in workspace yet; skipping cargo clippy."; \
	fi
	python3 -m ruff check orchestrator/ eval/ tests/

.PHONY: fmt
fmt: check-rust check-python ## Run cargo fmt + ruff format
	@if cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['workspace_members'] else 1)" 2>/dev/null; then \
		cargo fmt --all || exit 1; \
	else \
		echo "NOTE: No Rust crates in workspace yet; skipping cargo fmt."; \
	fi
	python3 -m ruff format orchestrator/ eval/ tests/

##@ Container

.PHONY: image
image: ## Build agent runner Docker image
	docker build -t athena-agents:latest .

##@ Utilities

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
