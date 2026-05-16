# Root developer workflow for CIDREYE/SYNapse.
# Keep all common commands here so contributors do not need to remember the
# nested Go module path or Python wrapper layout.

SHELL := /usr/bin/env bash
GO_MODULE_DIR := synapse
BINARY_NAME := synapse
BUILD_DIR := bin
GO_PACKAGE := ./$(GO_MODULE_DIR)/cmd/synapse
PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
GO ?= go

.PHONY: help deps build build-wrapper clean test test-go test-python run wrapper

help: ## Show available make targets.
	@awk 'BEGIN {FS = ":.*##"; printf "CIDREYE build targets:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Download Go modules and install Python dependencies.
	$(GO) -C $(GO_MODULE_DIR) mod download
	$(PIP) install -r $(GO_MODULE_DIR)/requirements.txt

build: ## Build the SYNapse scanner into ./bin/synapse.
	mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -o $(BUILD_DIR)/$(BINARY_NAME) $(GO_PACKAGE)

build-wrapper: build ## Build the scanner where the Python wrapper also auto-discovers it.
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GO_MODULE_DIR)/$(BINARY_NAME)

clean: ## Remove generated binaries and caches.
	rm -rf $(BUILD_DIR) $(GO_MODULE_DIR)/$(BINARY_NAME) $(GO_MODULE_DIR)/synapse_bin
	find . -type d \( -name __pycache__ -o -name .pytest_cache \) -prune -exec rm -rf {} +

test: test-go test-python ## Run all Go and Python tests.

test-go: ## Run Go tests from the root workspace.
	$(GO) test ./$(GO_MODULE_DIR)/...

test-python: ## Run Python tests for the wrapper and modules.
	cd $(GO_MODULE_DIR) && $(PYTHON) -m pytest -q

run: build ## Run the Go scanner. Pass ARGS="..." for scanner flags.
	./$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

wrapper: build ## Run the Python wrapper. Pass ARGS="..." for wrapper/scanner flags.
	$(PYTHON) $(GO_MODULE_DIR)/synapse.py $(ARGS)
