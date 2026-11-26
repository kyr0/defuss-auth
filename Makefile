SHELL := /bin/bash
.DEFAULT_GOAL := help
-include .env
export
BUN ?= bun
NODE ?= node
VAE ?= $(HOME)/defuss-vae/plugin/scripts/vae.py
.PHONY: help setup build lint test coverage integration e2e verify offline bench metrics start stop restart status log clean release vae
help: ## list available commands
	@awk -F':.*## ' '/^[a-zA-Z0-9_-]+:.*## /{printf "  %-15s %s\n", $$1, $$2}' $(firstword $(MAKEFILE_LIST))
setup: ## install pinned tools, dependencies and browser engines (first run generates bun.lock)
	@if command -v mise >/dev/null 2>&1; then mise install; fi
	@if [ -f bun.lock ]; then $(BUN) install --frozen-lockfile; else $(BUN) install; fi
	$(BUN) x playwright install chromium firefox webkit
build: ## build ESM/CJS and declarations with pkgroll
	$(BUN) run build
lint: ## strict TypeScript and oxlint
	$(BUN) run lint
test: ## Node and Bun tests against compiled internal modules
	$(BUN) run test
	$(BUN) run test:bun
coverage: ## coverage of executed source modules; thresholds fail closed
	@mkdir -p output; set -o pipefail; $(BUN) run coverage | tee output/coverage.txt
	@grep -qE '^. +auth\.js +\|' output/coverage.txt || { echo "coverage measured no source module; check --test-coverage-include/exclude"; exit 1; }
	@awk -F'|' '/all files/{gsub(/ /,"",$$2); print "TOTAL "$$2"%"}' output/coverage.txt
integration: build ## actual native defuss-db/storage, Node/Bun
	$(BUN) run test:native
e2e: build ## packed artifact, native persistence and browser OPFS
	$(BUN) run e2e
verify: lint test coverage e2e ## complete release gate
offline: ## restricted Node test gate; does not verify actual upstream adapters
	./scripts/verify-offline.sh
bench: ## measure memory-provider authentication
	$(BUN) run bench
metrics: ## report latest benchmark and coverage
	@cat output/benchmark.json output/coverage.txt
start: ## start explicit memory-only local demo
	$(BUN) run test:compile
	@mkdir -p tmp var/log; test ! -f tmp/demo.pid || ! kill -0 $$(cat tmp/demo.pid) 2>/dev/null; nohup $(NODE) examples/local-demo.mjs >var/log/demo.log 2>&1 & echo $$! >tmp/demo.pid
stop: ## stop local demo
	@if [ -f tmp/demo.pid ]; then kill $$(cat tmp/demo.pid) 2>/dev/null || true; rm -f tmp/demo.pid; fi
restart: stop start ## restart local demo
status: ## check demo status
	@test -f tmp/demo.pid && kill -0 $$(cat tmp/demo.pid) && echo running || echo stopped
log: ## display bounded demo logs
	@tail -80 var/log/demo.log
clean: ## remove build outputs
	rm -rf dist build output release
release: verify ## create npm tarball and full source ZIP, never publish
	@mkdir -p release; npm pack --ignore-scripts --pack-destination release
	python3 scripts/release.py
vae: ## run defuss-vae gate from an existing checkout
	python3 "$(VAE)" gate --repo .
