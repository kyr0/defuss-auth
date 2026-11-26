#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -n "${NODE_TYPE_ROOT:-}" ]]; then tsc -p tsconfig.offline.json --typeRoots "$NODE_TYPE_ROOT"; else tsc -p tsconfig.offline.json; fi
if [[ -n "${NODE_TYPE_ROOT:-}" ]]; then tsc -p tsconfig.types.offline.json --typeRoots "$NODE_TYPE_ROOT"; else tsc -p tsconfig.types.offline.json; fi
node --test --experimental-test-coverage --test-coverage-include='build/test/*.js' --test-coverage-exclude='tests/**' --test-coverage-lines=90 --test-coverage-branches=80 --test-coverage-functions=85 tests/*.test.mjs
