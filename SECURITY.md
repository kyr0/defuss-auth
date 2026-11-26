# Security and deployment contract

This is an authentication library candidate, not an independently audited production release. Use after the full release gates and security review. Report vulnerabilities privately through the maintainer rather than publishing exploitable credentials or logs.

## Required boundaries

- Deploy the authority behind authenticated TLS and configure trusted origins. Never enable a wildcard credentialed CORS policy. Cookie mode requires a same-site architecture, Secure/HttpOnly/SameSite cookies and an explicit CSRF header. Reserve all auth paths before static routes.
- Root API administrative methods are trusted operations, not unguarded RPC/MCP exports. Configure explicit authorization for HTTP administration. For app writes, combine a fresh authenticated principal with application-level transaction policy; the library cannot make an unrelated application database transaction atomic with auth state.
- Principals hold only effective claims. Authorization is exact string matching, not a role hierarchy. Service accounts are restricted to one tenant and cannot authenticate by password. Never use browser-local authority to establish a remote trust boundary.
- Enable passwordless login and registration only with a controlled delivery callback; prevent email links, tokens and passwords from reaching logs, analytics, referrers or third-party scripts. Handle delivery failure, retry and confirmation UX at the app level. Email challenge proof is not password proof; sensitive mutations require current-password step-up. Registration policy must be deterministic with respect to its input; external mutable policy needs application coordination.
- Password reset revokes prior credentials via epochs. Invitation claims must be explicitly authorized. Previously issued outstanding invitations remain valid until consumed, revoked, expired, or the tenant epoch changes; explicitly revoke outstanding invitations when rescinding an invitation policy. No automatic membership logic.
- Rate limiting uses bounded hashed buckets, source limits and global admission. Hash-bucket collisions can throttle unrelated accounts; this is a deliberate storage bound, not a complete DoS defense. Deploy edge/IP admission and appropriate per-deployment limits. Password KDF concurrency is bounded. Public challenge requests are non-enumerating by response body; timing equalization and email-delivery behavior depend on deployment.
- JWT verification pins Ed25519 and explicit `at+jwt` type, issuer/audience, time bounds, key ID, strict parsing and signature; legacy EdDSA is opt-in. Never authorize solely by offline signature verification or client-side decoded claims. The public JWKS route distributes verification keys, not a revocation oracle. Only the authority verifies current persisted state.

## Hosting several apps

- Configure `credential` on a host that app proxies reach. Without it the routes are public and the host ignores `X-Forwarded-For`, so only per-account and global limits apply. The secret is compared in constant time and removed before the handler runs.
- Trust `X-Forwarded-For` only through the chain: the service listener must trust the proxies' addresses, the app proxy must set the field from its socket peer, and `forwardedHops` must equal the number of trusted proxies in front of the app. A wrong count makes the limit apply to a proxy, or lets a client choose its key.
- Losing the host master key makes every app's signing keys unreadable. Back it up with the data root, and rotate it with a keyring.
- `tenantAdmin` trusts the claim holder with every member, grant, invitation and service account of its tenant, including grants of the admin claim itself.

## Administrative authorization

The policy callback may asynchronously evaluate its immutable snapshot. Before performing a guarded operation, the authority rechecks actor credential, grant revision, recent password proof and target state in the same provider transaction. If anything changed the operation fails. The provider must guarantee snapshot isolation with serializable/validated write commits; merely read-committed or best-effort wrappers are insufficient. Policies must not rely on mutable external state without their own transactional coordination. Avoid side effects in guards. No implicit interpretation of claim names. Explicitly deny global CRUD and list operations to tenant-only administrators.

## Key material

Generate master keys with a cryptographically secure generator and store them outside the database and key directory. Native persistent directories must be real, private owner-only paths. Back up database and encrypted keys consistently, protecting backups as sensitive. AES-GCM encrypts immutable JWK files with key ID, generation and version bound as associated data. Native private CryptoKeys are nonextractable after import. No secret can be protected against a compromised authority process.

Rotate signing keys via `maintain` or `rotateSigningKey`; use `revokePrevious:true` for compromise response. Normal retirement retains public keys conservatively for the maximum supported JWT lifetime plus skew. Revoke compromised retired keys immediately. `cleanup` removes expired metadata; it does not delete private files.

To rotate the encryption master key, stop/coordinate old authority instances, reopen with `keyRing: {activeVersion:'new',keys:{old:oldKey,new:newKey}}` (use `legacy` as the old version if initialized with `encryptionKey`), call `rewrapSigningKey()`, verify restart under the new key, and run `reconcileKeyFiles({exclusive:true})` only with all other processes/workers stopped. Keep old master keys as long as retained backups require them; remove obsolete key material according to backup policy. The active key ID does not change during rewrap. Publication uses CAS on the active key/generation; a failed publication leaves only an orphan file. `exclusive:true` is an operator assertion, not a distributed lock. A key namespace must belong to exactly one authority configuration.

## Audit and data retention

Durable mutation audit records are enabled by default and contain allowlisted metadata, not password hashes, tokens, emails or profile data. IDs, timestamps and application claim names can still be sensitive: restrict access to audit data. The audit cursor has at-least-once semantics; a failed external sink must not advance its cursor. Audit retention defaults to 90 days. Disabling durable audit requires an explicit configuration migration. Identity deletion is a soft tombstone, not regulatory erasure; implement coordinated data minimization/erasure and backup retention separately. Rate and expiration cleanup must be scheduled.

## Limitations and release gates

The release gate ran on macOS arm64 with Node.js 26 and Bun 1.4.4: native Argon2id, real defuss-db and defuss-storage, multiprocess refresh races with post-commit SIGKILL, OPFS in three browser engines, pkgroll output, the hosted deployment on defuss-serve 0.5.0 and the defuss-vae verifier. No independent cryptographic, concurrency, penetration or deployment audit has been performed. The 95% branch-coverage target remains open. Persistent format 2 intentionally refuses v0.1 stores; no automatic data migration. Federation, MFA and passkeys are intentionally excluded from this release. See VALIDATION.md.
