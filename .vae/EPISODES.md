2026-11-23 FINDING: replay across client session changes; encoded as client regression tests.
2026-11-23 FINDING: escaped provider transaction handles; encoded as scope-lifetime regression test.
2026-11-23 FINDING: encoded auth paths could be shadowed by static routing; encoded as route reservation regression test.
2026-11-23 DONE: offline Node 22 test suite 36/36; actual Bun, native defuss dependencies and browser gates UNKNOWN (no network/deps).
2026-11-23 DONE: v0.2 fixes the admin authorization TOCTOU and response cancellation cross-session replay; deterministic tests assert both invariants.
2026-11-23 DONE: offline Node 22 test suite 57/57 and schema inference type checks; native upstream, browser and package gates remain UNKNOWN.

2026-11-23T23:36:59Z s=2a2a1289 DONE fp=9860b9be51f0 cov=91.5% paths=.github/workflows/verify.yml,AGENTS.md,ARCH.md,CHANGELOG.md(+59)
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/keys.ts:StorageKeyStore.name learn=test: tests/v02.test.mjs 'encrypted key files use portable lowercase storage names across rewrap and reconcile' failed before, passes after; VERIFY rule storage.porta
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/serve.ts:createAuthHandler admin services/invitations learn=test: tests/v02.test.mjs 'admin service creation is authorized for the tenant it is created in' failed before (1 service in default), passes after; VERIFY rule securi
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/serve.ts:body learn=test: tests/v02.test.mjs 'HTTP mutations without payload accept the empty body stream Node adapters attach' failed before, passes after; VERIFY rule http.empty-body
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/index.ts:public type exports learn=test: scripts/package-e2e.mjs compiles a consumer with declaration emit; mutation check with old exports failed with 2x TS2742 + 1x TS4023; VERIFY rule package.declar
2026-11-23T23:36:59Z s=2a2a1289 FINDING package.json:scripts.coverage; Makefile:coverage learn=verifier: Makefile coverage fails when the report lists no source module (guard rejects the old empty report); VERIFY rule gate.coverage-nonempty
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/browser.ts:20; src/util.ts:210 learn=verifier: make lint (oxlint --deny-warnings) is part of make verify and the VAE gate
2026-11-23T23:36:59Z s=2a2a1289 FINDING package.json:scripts.e2e; scripts/http-e2e.mjs learn=verifier: package.json test:http in e2e; VERIFY rule e2e.every-route; route table mismatch or non-2xx fails the run
2026-11-23T23:36:59Z s=2a2a1289 FINDING scripts/native-e2e.mjs:dir learn=none: Harness-only; make integration exercises it on every run
2026-11-23T23:36:59Z s=2a2a1289 FINDING scripts/browser-e2e.mjs:engine.launch learn=none: Harness-only; make e2e runs all three engines on every run
2026-11-23T23:36:59Z s=2a2a1289 FINDING src/util.ts:string learn=test: tests/auth.test.mjs 'names, claims and emails reject control characters' fails under the mutation, passes on the real code
2026-11-26T11:03:07Z s=2a2a1289 DONE fp=9fccedc6dadb cov=90.5% paths=.github/workflows/verify.yml,AGENTS.md,ARCH.md,CHANGELOG.md(+63)
2026-11-26T11:03:07Z s=2a2a1289 FINDING src/host.ts:fetch learn=test: tests/host.test.mjs asserts 403 for /unknown/auth/me without the credential
2026-11-26T11:03:07Z s=2a2a1289 FINDING src/host.ts:authenticate learn=test: tests/host.test.mjs rejects 'member', [1] and {length:1} with INVALID_INPUT; fails before the fix with TypeError
2026-11-26T11:03:07Z s=2a2a1289 FINDING src/host.ts:HostedAppOptions learn=test: scripts/package-e2e.mjs compiles a peerless consumer re-exporting createAuthHost, authenticate, tenantAdmin and plugin results
2026-11-26T11:03:07Z s=2a2a1289 FINDING src/host.ts:tenantAdmin learn=verifier: tests/host.test.mjs DELETE /admin/tenants/acme answers 403; rule security.tenant-admin
2026-11-26T11:03:07Z s=2a2a1289 FINDING scripts/host-e2e.mjs:other app learn=memory: MEMORY line [hosting]
2026-11-26T11:03:07Z s=2a2a1289 FINDING scripts/host-e2e.mjs:rate check learn=verifier: rule security.host-forwarded-trust and e2e.hosted
2026-11-26T11:03:07Z s=2a2a1289 FINDING VALIDATION.md:53 learn=none: number sync, checked by reading the coverage report
2026-11-26T11:03:07Z s=2a2a1289 FINDING scripts/host-e2e.mjs:rate check comment learn=none: comment wording
2026-11-26T11:14:49Z s=2a2a1289 DONE fp=29438e23604f cov=90.0% paths=.github/workflows/verify.yml,AGENTS.md,ARCH.md,CHANGELOG.md(+63)
2026-11-26T11:14:49Z s=2a2a1289 FINDING scripts/host-e2e.mjs:proxy learn=verifier: e2e.hosted rule; host e2e prints the proxy it used
2026-11-26T11:14:49Z s=2a2a1289 FINDING VALIDATION.md:coverage row learn=memory: MEMORY line coverage variance
2026-11-26T11:22:30Z s=2a2a1289 DONE fp=29438e23604f cov=90.5% paths=.github/workflows/verify.yml,AGENTS.md,ARCH.md,CHANGELOG.md(+63)
