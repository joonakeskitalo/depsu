BIN := depsu
PREFIX ?= $(HOME)/.local

.DEFAULT_GOAL := help
.PHONY: help build release run test check fmt lint install uninstall clean

help: ## Show this help
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

build: ## Debug build
	cargo build

release: ## Optimized build (target/release/depsu)
	cargo build --release

run: ## Run in the current project (pass args with ARGS="--pm bun")
	cargo run -- $(ARGS)

test: ## Run unit tests
	cargo test

check: fmt-check lint test ## Format check, clippy and tests

fmt: ## Format code
	cargo fmt

fmt-check:
	cargo fmt --check

lint: ## Run clippy with warnings as errors
	cargo clippy --all-targets -- -D warnings

install: release ## Install to $(PREFIX)/bin
	install -d $(PREFIX)/bin
	install -m 755 target/release/$(BIN) $(PREFIX)/bin/$(BIN)

uninstall: ## Remove from $(PREFIX)/bin
	rm -f $(PREFIX)/bin/$(BIN)

clean: ## Remove build artifacts
	cargo clean
