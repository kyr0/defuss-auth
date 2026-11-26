# defuss-auth 0.2.0

Isomorphic authentication authority for Node.js, Bun and browsers. A small, instance-local API handles tenant-scoped claims, users, service accounts, password and email login, sessions, API keys, and recovery. The JWT and HTTP client exports have no runtime dependencies. Persistent defaults use defuss-db and defuss-storage. Every authenticated request verifies current persisted security state.

**Release candidate:** on macOS arm64, `make verify` passes on Node.js 26 and Bun 1.4.4. That run covers 67 domain tests per runtime, the real defuss-db and defuss-storage peers, multiprocess refresh races, every HTTP route over loopback HTTP, and the hosted deployment on defuss-serve 0.5.0. It also covers browser OPFS in Chromium, Firefox and WebKit, and the packed npm artifact. An independent security review is still an open release gate. See [VALIDATION.md](VALIDATION.md) and [SECURITY.md](SECURITY.md).

## Installation

```sh
make setup
make verify
make release
```

`make setup` installs the pinned Node.js 26 and Bun 1.4.4 toolchain when mise is available, resolves dependencies and installs Playwright engines. The first install creates `bun.lock`; no offline lockfile is fabricated. `make release` creates the source ZIP and npm tarball without publishing. Native use requires the upstream database and storage peers (`defuss-db@3.2.0`, `defuss-storage@0.4.1`). The core can run on Node.js 22+ with explicit providers and hashers. See [upstream contracts](docs/UPSTREAM.md).

## Quick start

```ts
import { createAuth } from 'defuss-auth/server';
import { authPlugin } from 'defuss-auth/serve';

const schemas = {
  user: {
    type: 'object',
    properties: { displayName: { type: 'string', minLength: 1 } },
    required: ['displayName'], additionalProperties: false,
  },
} as const;

const auth = await createAuth({
  issuer: 'https://api.example.com',
  audience: 'my-app',
  storage: { directory: './data/auth' },
  schemas,
});
const plugin = authPlugin(auth, {
  allowedOrigins: ['https://app.example.com'],
  ownAuth: true,
});
```

Supply a stable, randomly generated 32-byte master key through `DEFUSS_AUTH_MASTER_KEY` (base64url) or `encryptionKey`. Keep it in a secret manager, outside the encrypted JWK directory. The plugin implements the Fetch-style `name`, `matches`, `fetch`, `close` contract; reserve its namespace before static files in defuss-serve. Alternatively call `createAuthHandler(auth)` from any Fetch-compatible router. Actual defuss-serve integration is pending the upstream package.

## Users, tenants and claims

```ts
const user = await auth.createUser({
  email: 'alice@example.com', password: initialPassword,
  data: { displayName: 'Alice' },
});
const tenant = await auth.createTenant({ data: { name: 'Acme' } });
await auth.setClaims(user.id, tenant.id, ['documents:read', 'documents:write']);
await auth.grantClaim(user.id, tenant.id, 'billing:read');
await auth.revokeClaim(user.id, tenant.id, 'billing:read');
await auth.hasClaim(user.id, tenant.id, 'documents:write');
```

There is **no membership model or membership metadata API**. An internal authorization grant binds a subject ID, tenant ID and exact claim set. `setClaims(..., [])` allows entry to a tenant without granting any claims; `revokeTenantAccess` removes that access. Application memberships, roles, teams and other domain relationships belong to the application. Claims are opaque case-sensitive strings; no built-in special roles or wildcards. Emails are globally unique under an ASCII case-insensitive policy. The default tenant is created and users receive empty default access unless configured otherwise. Use `defaultTenant: { autoJoin: false }` or `{ enabled: false }` for explicit multi-tenant onboarding.

```ts
const p = await auth.requireAuth(request, {
  tenantId: requestedTenantId,
  claims: ['documents:write'],
});
const userId = p.subjectId;
const profile = await p.getUser();  // typed, optional and revalidated
const name = profile?.data.displayName;
```

Principals are immutable request-local capabilities, with `subjectId`, `subjectKind`, `tenantId`, effective `claims`, credential/session IDs and exact-match helpers. They expose no raw grant, identity profile or broader API-key permissions. Lazy hydration rechecks the original credential and current authorization state. `/me` returns only principal metadata unless the handler explicitly configures a projection.

## Service accounts and API keys

```ts
const worker = await auth.createServiceAccount({
  tenantId: tenant.id, name: 'document-indexer',
  claims: ['documents:read', 'embeddings:write'],
});
const { apiKey, record } = await auth.createApiKey({
  subjectId: worker.id, name: 'production', claims: ['documents:read'],
});
const p = await auth.authenticate('ApiKey ' + apiKey);
// p.subjectKind === 'service'; p.claims === ['documents:read']
await auth.rotateApiKey(record.id); // returns replacement plaintext once
```

Service accounts have no email or password and are bound to one tenant. Human users can also own API keys. Keys are opaque 256-bit secrets with indexed IDs and stored digests. The effective claims are the intersection of the key scope and current grants. Rotation revokes the previous key atomically. Default key lifetime is 90 days, maximum 365 days. Configure `apiKeyTtlMs`, `maxApiKeyTtlMs`, `apiKeyRotationTtlMs` (0 preserves original expiry). API-key principals cannot mint new credentials. Trusted server-side administrative methods can act without a principal; never expose those directly to untrusted RPC clients.

## Email-based authentication

```ts
const auth = await createAuth({
  issuer: 'https://api.example.com', audience: 'my-app',
  storage: { directory: './data/auth' },
  passwordless: true,
  registration: ({ email }) => email.endsWith('@example.com'),
  delivery: async event => sendAuthenticationEmail(event),
  policy: { requireVerifiedEmail: true },
});
```

`delivery` receives the event kind, email, single-use opaque token, expiry and optional tenant ID. Deliver tokens only through a verified TLS email-delivery channel; never log them. The application controls email templates and link UX. Email login and registration are opt-in. Registration creates a verified user only after the challenge is consumed; public registration can grant only empty default-tenant access. Invitations are explicitly issued for a tenant and claim set; an existing user's password and profile cannot be replaced by acceptance. Passwordless sessions lack recent password proof, so sensitive operations require password step-up. Password-only accounts can reset their password through the normal recovery flow; passwordless-only users may establish a password with email recovery if enabled by the application.

## Browser client

```ts
import { createAuthClient } from 'defuss-auth/client';
const client = createAuthClient({ baseUrl: 'https://api.example.com/auth', schemas });
await client.login({ email: 'alice@example.com', password: enteredPassword });
const response = await client.fetch('/documents');
await client.logout();
```

Cookie mode keeps access JWTs in memory and refresh tokens in Secure, HttpOnly, SameSite=Strict cookies. It requires explicit allowed origins and CSRF header verification. Use a same-site deployment or BFF. Token mode explicitly returns opaque refresh tokens in JSON for machine clients. Application requests attach credentials only to the configured origin, reject redirects, and retry only GET/HEAD with the same identity. The application must not authorize based on client-decoded claims.

## Persistence, maintenance and configuration

The isomorphic `createAuth` accepts an `AuthProvider`, `KeyStore` and `PasswordHasher`. `MemoryProvider` and `MemoryKeyStore` are for ephemeral/test operation. `DefussDbProvider` wraps an opened database; `StorageKeyStore` wraps a byte adapter and a master key/keyring. The `/browser` entry supports an explicitly local OPFS authority in a secure dedicated worker with `insecureLocalAuthority: true`. It is not a trusted identity authority for remote services.

Schedule `await auth.maintain(100)` with the defuss scheduler or your own scheduler. It rotates aged signing keys and removes expired records in bounded batches. Do not automatically delete key files: `reconcileKeyFiles({exclusive:true})` requires exclusive ownership across all processes and workers of the key namespace. Master-key rotation stages an immutable encrypted generation with `rewrapSigningKey()`; see [SECURITY.md](SECURITY.md). Durable security audit records are written in the mutation transaction by default; `deliverAudit({after,limit,deliver})` supports external at-least-once delivery. `telemetry` receives only operation names, durations, outcomes and safe codes, suitable for defuss-o11y.

Schema-derived TypeScript types propagate to authority and client. The default compiler validates a strict JSON Schema subset, emits bounded JSON Pointer issues, and rejects unsupported keywords. Supply a strict non-coercing compiler adapter for full JSON Schema. Configurations are fingerprinted; explicit `migrateFrom` and optional pure `migrateData` allow atomic schema/policy changes. Stale authority instances fail closed. Bump `policyVersion` when changing application callbacks or custom schema semantics.

**Breaking upgrade:** v0.2 uses persistent format 2; a v0.1 store is deliberately rejected. This candidate does not include an in-place v0.1 import tool. Provision a fresh authority or perform a separately reviewed offline migration; do not copy raw credential rows or accept old tokens into the new authority.

## Package exports

| Import | Responsibility |
| --- | --- |
| `defuss-auth` | Authority, types, schema, KDF interfaces |
| `defuss-auth/jwt` | Web Crypto JWT/JWK primitives |
| `defuss-auth/client` | Dependency-free Fetch client |
| `defuss-auth/server` | Native persistent configuration and Argon2id |
| `defuss-auth/browser` | Explicit browser-local OPFS authority |
| `defuss-auth/providers` | Persistence adapters |
| `defuss-auth/keys` | Encrypted JWK storage and keyring |
| `defuss-auth/serve` | Fetch transport and structural plugin |
| `defuss-auth/host` | One authority per app behind one endpoint, for a service that hosts auth for its apps ([guide](docs/HOSTING.md)) |

[API reference](docs/API.md) · [Architecture](ARCH.md) · [Security](SECURITY.md) · [Validation](VALIDATION.md) · [Changelog](CHANGELOG.md)
