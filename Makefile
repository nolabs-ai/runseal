# Runseal - Makefile
#
# Usage:
#   make          Build the CLI
#   make test     Run unit tests
#   make lint     Run clippy, format check, and version check (alias for check)
#   make ci       Simulate CI (lint + test)

.PHONY: all build test check lint clippy fmt fmt-check version-check clean ci audit audit-install help

CARGO ?= cargo
export RUSTFLAGS ?= -Dwarnings

TEST_FLAGS := --locked
ifeq ($(VERBOSE),1)
  TEST_FLAGS += --verbose
endif

all: build

build:
	$(CARGO) build --locked

test:
	$(CARGO) test $(TEST_FLAGS)

check: clippy fmt-check version-check

lint: check

clippy:
	$(CARGO) clippy --all-targets --locked -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

version-check:
	bash scripts/check-versions.sh

audit-install:
	$(CARGO) install cargo-audit --locked

audit:
	@command -v cargo-audit >/dev/null || { echo "cargo-audit not found; run make audit-install"; exit 1; }
	$(CARGO) audit

ci: lint test
	@echo "CI checks passed"

clean:
	$(CARGO) clean

help:
	@echo "Runseal Makefile targets:"
	@echo ""
	@echo "  make build         Build the CLI (debug)"
	@echo "  make test          Run unit tests (VERBOSE=1 for --verbose)"
	@echo "  make lint          Run clippy, format check, and version check"
	@echo "  make check         Same as lint"
	@echo "  make clippy        Run clippy only"
	@echo "  make fmt           Format code"
	@echo "  make fmt-check     Check formatting"
	@echo "  make version-check Check the release version agrees across all pinned sites"
	@echo "  make audit-install Install cargo-audit"
	@echo "  make audit         Run cargo audit"
	@echo "  make ci            Run lint and test (same as CI rust jobs)"
	@echo "  make clean         Remove build artifacts"
	@echo "  make help          Show this help"
