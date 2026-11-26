# Changelog

## 0.2.0 (candidate, 2026-11-23)

- Breaking: remove the public membership model and endpoints; use subject/tenant claim grants only. Compact request principals expose only effective claims with lazy revalidated profile hydration. Separate profile storage from security state; persistent format 2 refuses old-format stores.
- Fix admin authorization TOCTOU with transactional actor/target revalidation. Fix client cross-session replay during response-body cancellation. Verify service-key ownership on admin routes.
- Add service accounts and scoped API keys, configurable API-key expiration/rotation, email login, tenant invitations, opt-in registration, verified-email enforcement, password step-up and hash upgrade hooks.
- Add typed schema inference, compiled runtime validation and structured schema errors. Add explicit transactional configuration/schema migration and stale-instance fencing.
- Add durable redacted audit, cursor-based external delivery, telemetry, bounded admission, scheduled signing rotation, expiry cleanup, versioned master-key rewrap and exclusive key-file reconciliation.
- Split operation groups; cache cryptographic imports, parse JWT header once, use compact security-state snapshots.
- Add concurrency, replay, state-machine, schema type and operational regression tests. Add pending real upstream multiprocess/post-commit SIGKILL and independent JOSE interoperability gates.
- Fix: name encrypted key files with the hex key thumbprint. defuss-storage 0.4.1 rejected the mixed-case base64url names, so native and browser `createAuth` could not persist a signing key.
- Security fix: admin HTTP handlers for service accounts and invitations act on the tenant the policy authorized. Before, `POST /admin/services?tenantId=X` was authorized for X but created the service account in `default`.
- Fix: a `DELETE` without payload behind a Node HTTP adapter, which attaches an empty body stream, no longer fails with 400; only a non-empty payload needs `application/json`.
- Export the `AdminGuard` and `AuditRow` types so consumer declaration emit works. Make the coverage gate fail when it measures no source module; on Node 26 it had reported 100% without measuring any file.
- Add `defuss-auth/host`: one authority per app behind one Fetch endpoint, with per-app HKDF-derived keys, a proxy credential field, rate keys from the forwarded client of a credentialed proxy, a plain `authenticate` projection for RPC, `maintain` for every app, and the `tenantAdmin` policy. See docs/HOSTING.md.
- Widen the defuss-db peer to 3.2.0 or 3.3.0; the release gate passed with each. The native storage error for a symlinked or non-canonical directory now says to pass its realpath; tests cover both refusals and the owner-only checks.
- Document that cookie mode needs HTTPS in WebKit and that a page needs its origin listed in token mode too.
- Evidence: `make verify` passes on macOS arm64 with Node.js 26 and Bun 1.4.4, real defuss-db and defuss-storage, every HTTP route over loopback HTTP, and Chromium/Firefox/WebKit OPFS. See VALIDATION.md. defuss-serve and an independent security review remain open.

## 0.1.0 (candidate, 2026-11-23)

Initial Ed25519 JWT, password sessions, tenant-aware claims, API keys, persistence, encrypted signing keys, Fetch server/client and schema validation.
