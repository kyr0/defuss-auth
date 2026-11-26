# API reference

The root authority accepts `issuer`, `audience`, `provider`, `keyStore`, `passwordHasher`, optional `schemas`, `schemaValidator`, `policy`, `defaultTenant`, `delivery`, `passwordless`, `registration`, `durableAudit`, `audit`, `telemetry`, `tokenData`, `clock`, `ownProvider`, `migrateFrom`, `migrateData`, and `policyVersion`. Native and browser entry points provide the documented provider defaults. Source declarations are the definitive signatures.

## Identity and authorization

| Operation | Semantics |
| --- | --- |
| `createUser`, `getUser`, `getUserByEmail`, `userExists`, `listUsers`, `updateUser`, `deleteUser` | Global identity CRUD; unique canonical email, profile replacement, soft tombstone |
| `createTenant`, `getTenant`, `tenantExists`, `listTenants`, `updateTenant`, `deleteTenant` | Tenant CRUD, reserved default tenant |
| `createServiceAccount`, `getServiceAccount`, `listServiceAccounts`, `updateServiceAccount`, `deleteServiceAccount` | One-tenant machine identity CRUD, no email/password |
| `setClaims(subjectId, tenantId, claims)` | Create or replace access grant; empty claims permit tenant login |
| `getClaims(subjectId, tenantId)` | Trusted raw grant claim lookup, undefined for absent grant |
| `listTenantIds(subjectId,page?)` | List grant tenant IDs (not a guarantee of active credentials) |
| `revokeTenantAccess(subjectId,tenantId)` | Delete the grant, invalidate incarnation |
| `grantClaim`, `revokeClaim`, `hasClaim` | Atomic exact string mutation or live check |
| `authenticate(headerOrRequest,{tenantId?})` | Verify JWT or API key against live security state |
| `requireAuth(headerOrRequest,{tenantId?,claims?,anyClaims?})` | Authenticate and require exact claims |

A `Principal` exposes subject/tenant IDs, subject kind, effective claims, credential and optional session/token IDs, and claim helpers. `getUser()`, `getTenant()`, `getServiceAccount()` revalidate and lazily hydrate the corresponding profile. User principals return undefined for service hydration and vice versa. Raw grant fields are never exposed on a principal. Do not serialize a principal as proof or hold it across requests. `setClaims` and identity methods without a guard are trusted server-local administrative operations.

## Sessions, credentials and recovery

| Operation | Semantics |
| --- | --- |
| `login({email,password,tenantId?,rateKey?})` | Password proof, tenant-bound session; optional verified-email policy |
| `refresh(refreshToken)` | Opaque single-use rotation and valid replay detection |
| `switchTenant(principal,tenantId)` | Issue tenant-bound session using authorized grant |
| `stepUp(principal,currentPassword)` | Verify password and replace the old session |
| `logout`, `logoutRefresh`, `logoutAll`, `revokeToken`, `listSessions`, `revokeSession` | Session/token lifecycle; sensitive operations require recent proof |
| `requestPasswordReset(email,rateKey?)`, `resetPassword(token,newPassword)` | Email recovery; reset invalidates old credentials |
| `requestEmailVerification(email,rateKey?)`, `verifyEmail(token)` | Confirm email ownership |
| `changePassword`, `setPassword` | Authenticated change or trusted administrative set |
| `requestPasswordlessLogin({email,tenantId?,rateKey?})`, `confirmPasswordlessLogin(token)` | Opt-in email challenge; no password step-up proof |
| `requestRegistration({email,data?,rateKey?})`, `confirmRegistration({token,password?})` | Opt-in policy; email proof before account creation, no privileged claims |
| `inviteToTenant({email,tenantId,claims?})`, `revokeInvitation(id)`, `acceptInvitation({token,password?,data?})` | Trusted tenant-specific invite; one use; existing account must accept without password/profile changes |

Email delivery is a callback. Public challenge requests return no user-existence result. An application should use equivalent timing and UX for email delivery and handle retries; delivery is not a durable outbox. All sensitive flows should use TLS and rate-limited, non-enumerating endpoints. Custom `PasswordHasher.needsRehash` supports migration on successful login; a replacement hasher must verify existing encodings. Native Argon2id and browser PBKDF2 are supplied. Passwordless-only accounts cannot perform password-step-up operations until a password is established.

## API keys and operations

`createApiKey({subjectId,userId?,tenantId?,name,claims?,expiresAt?}, principal?)`, `getApiKey`, `listApiKeys`, `updateApiKey`, `revokeApiKey`, `rotateApiKey`. `userId` is an optional compatibility alias for `subjectId`. Service tenant is inferred; human tenant defaults to `default`. Plaintext is returned only on create/rotate; metadata has no digest. Optional principals restrict self-service to the same user and tenant and, for sensitive writes, require a recent password proof. Keys must have finite expiry. Scope update can only reduce scope; use new keys for expanded permissions.

`jwks`, `rotateSigningKey({revokePrevious?,expectedKid?})`, `revokeSigningKey`, `rewrapSigningKey`, `reconcileKeyFiles({exclusive:true,limit?})`, `cleanup(limit?)`, `maintain(limit?)`, `configurationFingerprint()`, `listAudit(page?)`, `deliverAudit({after?,limit?,deliver})`, `close()`. `maintain` rotates an aged signing key and cleans expired rows. Cleanup bounds deletions per collection. Outbox delivery is at least once; persist the returned cursor only after delivery succeeds and deduplicate by audit ID. Audit retention bounds recoverability. `reconcileKeyFiles` requires operator-enforced exclusivity across all authorities.

## HTTP contract

Relative to `/auth`, except the absolute JWKS route. Errors return `{error: CODE}` and optional structured schema issues. No raw exceptions, access tokens in URLs or private key material. Cookie mode requires explicitly trusted origins and the CSRF header; token mode is explicit. A request payload is a JSON object sent as `application/json`; a mutation without payload may omit the body and the content type. A request with an `Origin` outside `allowedOrigins` answers 403 in both modes, so a page needs its origin listed even in token mode. VERIFIED: (browser probe, 2026-11-26) WebKit 26.6 drops the `Secure` refresh cookie on `http://127.0.0.1`, while Chromium 153 and Firefox 155 keep it; serve cookie mode over HTTPS. The client offers typed wrappers for the routes below.

| Method | Path |
| --- | --- |
| POST | `/login`, `/refresh`, `/logout`, `/logout-all`, `/token/revoke` |
| POST | `/login/email/request`, `/login/email/confirm` |
| POST | `/register/request`, `/register/confirm`, `/invitation/accept` |
| GET | `/me`, `/sessions`, `/tenants` |
| DELETE | `/sessions/:id` |
| POST | `/tenant/switch`, `/password/step-up`, `/password/change` |
| POST | `/password/reset/request`, `/password/reset/confirm`, `/email/verify/request`, `/email/verify/confirm` |
| GET, POST | `/api-keys` |
| GET, PATCH, DELETE | `/api-keys/:id` |
| POST | `/api-keys/:id/rotate` |
| GET | `/.well-known/jwks.json` |
| GET, POST | `/admin/users`, `/admin/tenants`, `/admin/services` |
| GET, PATCH, DELETE | `/admin/users/:id`, `/admin/tenants/:id`, `/admin/services/:id` |
| GET | `/admin/users/:id/claims`, `/admin/services/:id/claims` |
| GET, PUT, DELETE | `/admin/users/:id/claims/:tenantId`, `/admin/services/:id/claims/:tenantId` |
| POST | `/admin/invitations` |
| DELETE | `/admin/invitations/:id` |
| GET, POST | `/admin/services/:id/api-keys` |
| GET, PATCH, DELETE | `/admin/services/:id/api-keys/:keyId` |
| POST | `/admin/services/:id/api-keys/:keyId/rotate` |

Admin routes are absent without `authorizeAdmin`. A callback receives a verified human JWT principal plus immutable method/resource/target information and sanitized request body. Authorize the exact target, tenant, requested claims and mutation. Service-account and invitation routes take the tenant from the body `tenantId`, else the `tenantId` query parameter; creating and listing service accounts falls back to `default`. The handler acts on exactly the tenant it passed to the policy. No automatic role or tenant-admin semantics. Global user/tenant listing is global and must be denied to tenant-only administrators; implement scoped lists at the application layer. The guard repeats actor and target checks inside the protected transaction, not arbitrary external policy checks. All sensitive admin routes require fresh password proof. Optional `projectPrincipal` controls additional `/me` data and must avoid disclosing private application fields.

## Hosting several apps

`createAuthHost({directory, masterKey | keyRing, basePath?, credential?})` from `defuss-auth/host` returns a host. `open(app, options)` creates an app's authority in `<directory>/<app>` with a key derived by HKDF-SHA-256 from the master key and the app name. It takes the `defuss-auth/server` options except storage and keys, plus `http` (handler options) and `forwardedHops`. App names are lowercase `[a-z0-9_-]`, 1 to 64 characters. `fetch(request)` and `plugin()` serve `<basePath>/<app>/<path>` (default base `/apps`) by passing `<path>` to that app's handler. So the handler's `prefix` must be the path at which the app's proxy mounts it. With `credential: {header, secret}`, a request without that field and secret answers 403, and the field is removed before the handler runs. Only then does the handler's rate key come from `X-Forwarded-For`: the entry `forwardedHops` places left of the right end. `authenticate(app, authorization, {tenantId?, claims?, anyClaims?})` returns a plain projection of the live principal. `get(app)` returns the authority for trusted calls. `maintain(limit?)` maintains every app and reports per app. `close(app)` and `closeAll()` close authorities. `tenantAdmin(claim)` is an `authorizeAdmin` policy for administrators of the targeted tenant; it refuses global user and tenant routes. [Integration guide](HOSTING.md).

## JSON Schema and types

The built-in validator supports boolean schemas, `type`, `enum`, `const`, `properties`, `required`, `additionalProperties`, `items`, `allOf`, `anyOf`, `oneOf`, `not`, string/array/object length bounds, numeric bounds, `uniqueItems`, basic email/URI/date-time formats. Annotations have no validation effect. Unsupported assertions such as `$ref` or `pattern` fail initialization rather than being ignored. The compiler emits up to 32 JSON Pointer issues. Custom compilers must be strict, synchronous, non-coercing and network-free. Schema inference covers common object, required, enum, union and array types; runtime validation remains authoritative. Use `as const` schemas and pass the same schemas to the client for inferred types. TypeScript cannot express every JSON Schema constraint.
