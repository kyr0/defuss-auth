# Verification evidence: v0.2.0 candidate

## Executed release gate (2026-11-26)

Environment: macOS (Darwin 25.6.0) arm64, Node.js 26.13.1, Bun 1.4.4 (pinned through mise), TypeScript 5.8.3, oxlint 1.90.0, pkgroll 2.29.0, Playwright 1.63.0. Installed peers: defuss-db 3.3.0 and defuss-storage 0.4.1 from the registry; development dependency defuss-serve 0.5.0. `bun.lock` comes from that install.

VERIFIED: `make verify` (lint, test, coverage, e2e) exits 0. The defuss-vae 0.9.0 verifier proves every configured check, including the 17 project rules in `.vae/VERIFY.py`. The peer range admits defuss-db 3.2.0 and 3.3.0: the same gate passed with 3.2.0 earlier on 2026-11-26, before the development pin moved to 3.3.0.

| Gate | Command | Result |
| --- | --- | --- |
| Strict TypeScript against the installed peer declarations, schema-inference type tests, oxlint `--deny-warnings` | `make lint` | passed |
| Domain suite on Node and Bun, including `defuss-auth/host` | `make test` | 69/69 passed on each runtime, no skips |
| Coverage of compiled source modules | `make coverage` | 91.06% lines, 84.68% branches, 87.48% functions ([raw report](docs/evidence/node26-darwin-coverage.txt)). VERIFIED: identical runs alternate between this report and 91.52/84.82/87.48, because `serve.js` admin service lines that `tests/host.test.mjs` executes are sometimes missing from the merged report. UNKNOWN: the cause inside Node's coverage merge; the lower figures are quoted |
| Packed npm artifact: ESM and CJS on Node and Bun, consumer declaration emit | `scripts/package-e2e.mjs` | passed |
| Independent JOSE 6.1.0 EdDSA interoperability, Node and Bun | `scripts/jose-interop.mjs` | passed |
| Real defuss-db and defuss-storage: unique email under concurrency, restart, refresh race, service keys, rotation, master-key rewrap and reconciliation, Argon2id PHC exchange between Node and Bun | `scripts/native-e2e.mjs` | passed on Node and Bun |
| Multiprocess refresh race; SIGKILL after a committed refresh, then restart and replay | `scripts/native-concurrency.mjs` | passed on Node and Bun |
| All 59 HTTP routes over loopback HTTP, the built package, real defuss-db/storage and Argon2id, Node and Bun | `scripts/http-e2e.mjs` | passed |
| Hosted deployment: an app server's `proxyPlugin` forwards `/auth` to `host.plugin()`, both on defuss-serve 0.5.0. Real storage and Argon2id; a proxy credential; rate keys over both listeners; restart; per-app keys; tenant administration. Chromium 153 and Firefox 155 in cookie mode, WebKit 26.6 in token mode | `scripts/host-e2e.mjs` | passed on Node and Bun |
| Real OPFS in a dedicated worker: Chromium 153, Firefox 155, WebKit 26.6 | `scripts/browser-e2e.mjs` | passed |

The e2e result files are in [docs/evidence/node26-darwin-e2e.json](docs/evidence/node26-darwin-e2e.json).

## Defects found by the 2026-11-24 run

Each was fixed in the 0.2.0 candidate. Every library and gate fix has a regression check listed in `.vae/VERIFY.py`; the harness fixes are covered by the gates they unblocked.

- Key-file names: `StorageKeyStore` used the mixed-case base64url key ID, but defuss-storage 0.4.1 accepts only portable lowercase names. `createAuth` from `defuss-auth/server` and `defuss-auth/browser` could not persist its first signing key. File names hex-encode the key thumbprint. Test: `encrypted key files use portable lowercase storage names across rewrap and reconcile`.
- Admin tenant binding: `POST /admin/services?tenantId=X` was authorized for tenant X but created the service account in the body's tenant, which defaulted to `default`. A tenant-scoped administrator could create a service account with arbitrary claims in another tenant. The service-account and invitation handlers act on the authorized tenant only. Test: `admin service creation is authorized for the tenant it is created in`.
- Bodiless mutations: Node HTTP adapters attach an empty body stream to every non-GET request, and the handler rejected those `DELETE` requests with 400 because they had no JSON content type. Only a non-empty payload needs `application/json`. Found by `scripts/http-e2e.mjs`; test: `HTTP mutations without payload accept the empty body stream Node adapters attach`.
- Public types: `AdminGuard` and `AuditRow` were not exported, so a consumer that re-exported results of `prepareAdmin`, `listAudit` or `deliverAudit` failed declaration emit with TS2742/TS4023. The package e2e compiles such a consumer.
- Coverage gate: on Node 26 the default test-file exclusion matched `build/test/**`, so the gate measured zero files and reported 100%. Coverage excludes only `tests/**`, and `make coverage` fails when the report lists no source module.
- Test harness: `native-e2e.mjs` canonicalizes its macOS temp directory (`/var` links to `/private/var`), which the storage directory contract rejects. `browser-e2e.mjs` uses persistent browser profiles, because private-browsing WebKit contexts reject `navigator.storage.getDirectory()`.

## Local benchmark

MemoryProvider, one user, serial requests, 30 warmups and 1,000 samples per credential, Node.js 26.13.1 on darwin arm64. [Raw JSON](docs/evidence/node26-darwin-benchmark.json).

| Path | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| JWT | 0.095 ms | 0.228 ms | 0.335 ms |
| API key | 0.020 ms | 0.042 ms | 0.091 ms |

These numbers do not measure persistent-database throughput. Because the hardware and runtime differ from the earlier Node 22 Linux run ([raw JSON](docs/evidence/node22-benchmark.json)), the two runs cannot be compared. Run `make bench` on the target hardware.

## Open release requirements

| Requirement | Status |
| --- | --- |
| Actual defuss-serve plugin compatibility | VERIFIED for defuss-serve 0.5.0: `scripts/host-e2e.mjs` mounts `host.plugin()` and the app's `proxyPlugin` on two real listeners (Node and Bun). UNKNOWN: other defuss-serve versions, and the defuss-backplane integration |
| Independent security review, fault injection inside native commits, deployment load test | UNKNOWN: an agent code review ran; no independent audit, fault injection or load test |
| Linux and Windows runtime gates | UNKNOWN: this run covers macOS arm64 only; CI (`.github/workflows/verify.yml`) runs on Ubuntu |
| 95% branch and security-critical coverage target | open: branches are at 84.68%, above the 80% gate floor |

The offline gate (`make offline`) stays a narrow Node-only check against the bridge declarations in `tests/types/upstream.d.ts`. It is not evidence that the upstream adapters work. The source archive from `make release` is not a verified npm package; `make release` never publishes.
