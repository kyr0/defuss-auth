import { createAdminOperations } from './admin.js';
import { createApiKeysOperations } from './api-keys.js';
import { auditProjection } from './audit.js';
import { createChallengesOperations } from './challenges.js';
import { assertActive,next,sameClaims,type OperationsContext,type State } from './context.js';
import { createIdentityOperations } from './identity.js';
import { genEd25519Pair,importPrivate,importPublic,prepareJwt,registeredClaims,signJwt,type JwtClaims } from './jwt.js';
import type { KeyStore } from './keys.js';
import { createLifecycleOperations } from './lifecycle.js';
import { boundedHasher,type PasswordHasher } from './password.js';
import { separateProfiles,type AuthorityProvider,type AuthReadStore,type AuthWriteStore } from './persistence.js';
import { TransactionConflict,type AuthProvider,type ListOptions } from './providers.js';
import { grantId,publicService,publicTenant,publicUser,type AuditRow,type Challenge,type Session,type SigningKey,type Table,type Tables } from './records.js';
import { createStrictSchemaValidator,type SchemaData,type SchemaSet,type SchemaValidator } from './schema.js';
import { createSessionsOperations } from './sessions.js';
import { AuthError,b64,dataCopy,fail,freeze,id,identifier,integer,jsonCopy,opaque,opaqueId,parseAuthorization,random,sha,string,tag,verifyTag,type Data } from './util.js';
export interface AuthPolicy {
    accessTtlSec?: number;
    clockToleranceSec?: number;
    sessionTtlMs?: number;
    idleTtlMs?: number;
    apiKeyTtlMs?: number;
    maxApiKeyTtlMs?: number;
    challengeTtlMs?: number;
    passwordMinLength?: number;
    recentProofMs?: number;
    rateWindowMs?: number;
    rateAttempts?: number;
    legacyEdDSA?: boolean;
    requireVerifiedEmail?: boolean;
    globalRateAttempts?: number;
    signingKeyMaxAgeMs?: number;
    apiKeyRotationTtlMs?: number;
    auditRetentionMs?: number;
}
export interface Delivery {
    kind: Challenge['kind'];
    email: string;
    token: string;
    expiresAt: number;
    tenantId?: string;
}
export interface AuditEvent {
    type: string;
    at: number;
    userId?: string;
    tenantId?: string;
    changes?: AuditRow['changes'];
}
export interface AuthOptions<S extends SchemaSet = SchemaSet> {
    issuer: string;
    audience: string;
    provider: AuthProvider;
    keyStore: KeyStore;
    passwordHasher: PasswordHasher;
    schemas?: S;
    schemaValidator?: SchemaValidator;
    defaultTenant?: {
        enabled?: boolean;
        autoJoin?: boolean;
        data?: Data;
    };
    policy?: AuthPolicy;
    delivery?: (event: Delivery) => Promise<void>;
    durableAudit?: boolean;
    /** Registration is disabled unless a policy explicitly allows this email and data. */
    registration?: (input: Readonly<{
        email: string;
        tenantId: string;
        data: Data;
    }>) => boolean | Promise<boolean>;
    passwordless?: boolean;
    /** Coordinated configuration changes require an explicitly approved previous fingerprint. */
    migrateFrom?: string;
    /** Bump when changing application policy callbacks or external schema semantics. */
    policyVersion?: string;
    /** Pure data transform, executed in the schema migration transaction. */
    migrateData?: (kind: 'user' | 'tenant' | 'service', value: Data) => Data;
    telemetry?: (event: {
        operation: string;
        outcome: 'ok' | 'error';
        durationMs: number;
        code?: string;
    }) => void;
    audit?: (event: AuditEvent) => void | Promise<void>;
    tokenData?: (context: {
        userId: string;
        tenantId: string;
        claims: readonly string[];
    }) => Data;
    clock?: () => number;
    ownProvider?: boolean;
}
export interface Principal {
    readonly subjectId: string;
    readonly subjectKind: 'user' | 'service';
    readonly tenantId: string;
    getUser(): Promise<ReturnType<typeof publicUser> | undefined>;
    getTenant(): Promise<ReturnType<typeof publicTenant>>;
    getServiceAccount(): Promise<ReturnType<typeof publicService> | undefined>;
    readonly claims: readonly string[];
    readonly method: 'jwt' | 'apiKey';
    readonly credentialId: string;
    readonly sessionId?: string;
    readonly tokenId?: string;
    hasClaim(claim: string): boolean;
    hasAllClaims(claims: readonly string[]): boolean;
    hasAnyClaim(claims: readonly string[]): boolean;
}
export interface SessionTokens {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    sessionId: string;
    refreshExpiresAt: number;
}
export type AdminGuard = ((store: AuthReadStore) => Promise<void>) & {
    readonly actorId?: string;
    readonly tenantId?: string;
};
export interface AdminOperation {
    method: string;
    resource: string;
    id?: string;
    keyId?: string;
    tenantId?: string;
    body: Readonly<Record<string, unknown>>;
}
const DAY = 86400000;
const canonical = (x: unknown): unknown => Array.isArray(x) ? x.map(canonical) : x && typeof x === 'object' ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => [k, canonical(v)])) : x;
/** Construct an isolated authority. All security-state changes use a provider transaction. */
async function createAuthority(options: AuthOptions) {
    // Capture application configuration; callers cannot mutate a live authority by editing the options object.
    options = Object.freeze({ ...options });
    const { keyStore } = options;
    const backingProvider = separateProfiles(options.provider);
    let initialized = false;
    const provider: AuthorityProvider = {
        init: () => backingProvider.init(), close: () => backingProvider.close(),
        read: fn => backingProvider.read(async (r) => { if (initialized)
            await verifyConfig(r); return fn(r); }),
        transaction: fn => backingProvider.transaction(async (w) => { if (initialized)
            await verifyConfig(w); return fn(w); })
    };
    if ((options.passwordless || options.registration) && !options.delivery)
        fail('INVALID_INPUT', 'Email delivery required for email-based authentication');
    const issuer = string(options.issuer, 512), audience = string(options.audience, 512);
    const p = { accessTtlSec: 900, clockToleranceSec: 30, sessionTtlMs: 30 * DAY, idleTtlMs: 7 * DAY, apiKeyTtlMs: 90 * DAY, maxApiKeyTtlMs: 365 * DAY, challengeTtlMs: 900000, passwordMinLength: 15, recentProofMs: 300000, rateWindowMs: 900000, rateAttempts: 10, legacyEdDSA: false, requireVerifiedEmail: false, globalRateAttempts: 10000, signingKeyMaxAgeMs: 30 * DAY, apiKeyRotationTtlMs: 0, auditRetentionMs: 90 * DAY, ...options.policy };
    integer(p.accessTtlSec, 30, 86400);
    integer(p.clockToleranceSec, 0, 300);
    integer(p.sessionTtlMs, 60000, 365 * DAY);
    integer(p.idleTtlMs, 60000, p.sessionTtlMs);
    integer(p.apiKeyTtlMs, 60000, p.maxApiKeyTtlMs);
    integer(p.maxApiKeyTtlMs, 60000, 10 * 365 * DAY);
    integer(p.challengeTtlMs, 60000, DAY);
    integer(p.passwordMinLength, 15, 128);
    integer(p.recentProofMs, 1000, DAY);
    integer(p.rateWindowMs, 1000, DAY);
    integer(p.rateAttempts, 1, 10000);
    integer(p.globalRateAttempts, 1, 1000000);
    integer(p.signingKeyMaxAgeMs, 60000, 365 * DAY);
    integer(p.apiKeyRotationTtlMs, 0, p.maxApiKeyTtlMs);
    integer(p.auditRetentionMs, DAY, 10 * 365 * DAY);
    const now = () => integer((options.clock ?? Date.now)(), 0, Number.MAX_SAFE_INTEGER - 10 * 365 * DAY);
    const hasher = boundedHasher(options.passwordHasher);
    const schemas = freeze(jsonCopy(options.schemas ?? {})) as AuthOptions['schemas'];
    const validator = options.schemaValidator ?? createStrictSchemaValidator();
    for (const schema of Object.values(schemas ?? {}))
        validator.check(schema);
    function data(kind: keyof NonNullable<AuthOptions['schemas']>, value: unknown): Data {
        const d = dataCopy(value);
        const s = schemas?.[kind];
        if (s !== undefined) {
            const before = JSON.stringify(d);
            validator.validate(s, d);
            if (JSON.stringify(d) !== before)
                fail('SCHEMA', 'Schema validators must not mutate data');
        }
        return d;
    }
    const defaultEnabled = options.defaultTenant?.enabled !== false, autoJoin = options.defaultTenant?.autoJoin !== false;
    const defaultData = defaultEnabled ? data('tenant', options.defaultTenant?.data ?? {}) : {};
    const schemaHash = await sha(JSON.stringify(canonical({ schemas, defaultEnabled })));
    const configHash = await sha(JSON.stringify(canonical({ schemaHash, policy: p, autoJoin, passwordless: !!options.passwordless, registration: !!options.registration, durableAudit: options.durableAudit !== false, policyVersion: options.policyVersion === undefined ? '1' : string(options.policyVersion, 128) })));
    async function verifyConfig(r: AuthReadStore) { const m = await r.get('meta', 'authority'); if (m?.configHash !== configHash)
        fail('UNAVAILABLE', 'Authority configuration changed; reopen'); }
    const dummyHash = await hasher.hash(b64(random(32)));
    let closing = false, active = 0, exclusiveMaintenance = false;
    let drain: () => void = () => {
    };
    let closePromise: Promise<void> | undefined;
    const publicCache = new Map<string, Promise<CryptoKey>>(), privateCache = new Map<string, Promise<CryptoKey>>();
    function cached(cache: Map<string, Promise<CryptoKey>>, kid: string, load: () => Promise<CryptoKey>) {
        let k = cache.get(kid);
        if (!k) {
            if (cache.size >= 64)
                cache.delete(cache.keys().next().value!);
            k = load();
            cache.set(kid, k);
            void k.catch(() => {
                if (cache.get(kid) === k)
                    cache.delete(kid);
            });
        }
        return k;
    }
    async function read<T>(fn: (r: AuthReadStore) => Promise<T>, guard?: AdminGuard): Promise<T> {
        return provider.read(async (r) => { await guard?.(r); return fn(r); });
    }
    async function tx<T>(fn: (w: AuthWriteStore) => Promise<T>, guard?: AdminGuard, auditContext?: {
        actorId?: string;
        tenantId?: string;
    } | false): Promise<T> {
        for (let i = 0;; i++) {
            try {
                const committed = await provider.transaction(async (w) => {
                    await guard?.(w);
                    const changes: AuditRow['changes'] = [];
                    const enabled = options.durableAudit !== false && auditContext !== false;
                    async function change(k: Table, key: string, action: AuditRow['changes'][number]['action'], after?: unknown) {
                        if (!enabled || k === 'rates' || k === 'audit' || k === 'auditState' || k === 'profiles')
                            return;
                        const before = action === 'insert' ? undefined : await w.get(k, key);
                        changes.push({ table: k, id: key, action, before: auditProjection(k, before), after: auditProjection(k, after) });
                    }
                    const wrapped: AuthWriteStore = { ...w,
                        async insert(k, r) { await change(k, r.id, 'insert', r); await w.insert(k, r); },
                        async put(k, r) { await change(k, r.id, 'put', r); await w.put(k, r); },
                        async delete(k, key) { await change(k, key, 'delete'); await w.delete(k, key); },
                        async putCompact(k, r) { await change(k, r.id, 'put', r); await w.putCompact(k, r); }
                    };
                    const value = await fn(wrapped);
                    let event: AuditRow | undefined;
                    if (changes.length) {
                        const at = now(), head = await w.get('auditState', 'head'), sequence = next(head?.sequence ?? 0);
                        await w.put('auditState', { id: 'head', sequence });
                        event = { id: String(sequence).padStart(16, '0'), at, expiresAt: at + p.auditRetentionMs, changes, actorId: guard?.actorId || (auditContext || {}).actorId, tenantId: guard?.tenantId || (auditContext || {}).tenantId };
                        await w.insert('audit', event);
                    }
                    return { value, event };
                });
                if (committed.event)
                    await emit({ type: 'transaction.committed', at: committed.event.at, userId: committed.event.actorId, tenantId: committed.event.tenantId, changes: committed.event.changes });
                return committed.value;
            }
            catch (e) {
                if (!(e instanceof TransactionConflict) || i >= 4)
                    throw e;
                await new Promise(r => setTimeout(r, 2 ** i));
            }
        }
    }
    async function get<K extends Table>(r: AuthReadStore, table: K, k: string): Promise<Tables[K]> {
        const v = await r.get(table, k);
        if (!v)
            fail('NOT_FOUND');
        return v;
    }
    async function state(r: AuthReadStore, userId: string, tenantId: string, verifyEmail = true): Promise<State> {
        const m = await r.get('grants', grantId(userId, tenantId));
        if (!m)
            fail('UNAUTHENTICATED');
        const u = await r.getCompact('users', userId) ?? await r.getCompact('services', userId);
        const t = await r.getCompact('tenants', tenantId);
        assertActive(u);
        assertActive(t);
        if (!m || u?.kind === 'service' && u.tenantId !== tenantId)
            fail('UNAUTHENTICATED');
        if (verifyEmail && u?.kind === 'user' && p.requireVerifiedEmail && !u.emailVerified)
            fail('UNAUTHENTICATED');
        if (m!.userId !== userId || m!.tenantId !== tenantId)
            fail('UNAVAILABLE');
        return { u: u!, t: t!, m: m! };
    }
    function matchEpoch(s: {
        incarnation: string;
        userEpoch: number;
        tenantEpoch: number;
    }, st: State) {
        return s.incarnation === st.m.incarnation && s.userEpoch === st.u.epoch && s.tenantEpoch === st.t.epoch;
    }
    function sessionValid(s: Session, st: State, time: number) {
        return matchEpoch(s, st) && s.revokedAt === null && s.expiresAt > time && s.idleUntil > time && s.userSessionEpoch === st.u.sessionEpoch && s.grantSessionEpoch === st.m.sessionEpoch;
    }
    async function loadSession(r: AuthReadStore, sid: string, time: number) {
        const s = await r.get('sessions', sid);
        if (!s)
            fail('UNAUTHENTICATED');
        const st = await state(r, s.userId, s.tenantId);
        if (!sessionValid(s, st, time))
            fail('UNAUTHENTICATED');
        return { s, st };
    }
    async function emit(event: AuditEvent) {
        try {
            await options.audit?.(freeze(event));
        }
        catch { /* Observers cannot roll back a committed security action. */
        }
    }
    async function throttle(kind: string, key: string, limit = p.rateAttempts) {
        // Bounded hash buckets prevent unbounded durable rows from unauthenticated input.
        const hash = await sha(kind + '\0' + key), k = kind + ':' + (kind === 'public-global' ? 'all' : hash.slice(0, 2));
        const ok = await tx(async (w) => {
            const time = now(), old = await w.get('rates', k);
            if (old && old.expiresAt > time && old.count >= limit)
                return false;
            await w.put('rates', { id: k, count: old && old.expiresAt > time ? old.count + 1 : 1, expiresAt: old && old.expiresAt > time ? old.expiresAt : time + p.rateWindowMs });
            return true;
        });
        if (!ok)
            fail('RATE_LIMIT');
    }
    async function signingKey(r: AuthReadStore) {
        const meta = await get(r, 'meta', 'authority');
        const k = await get(r, 'keys', meta.activeKid);
        if (k.state !== 'active')
            fail('UNAVAILABLE', 'No active signing key');
        return k;
    }
    async function privateKey(k: SigningKey) {
        return cached(privateCache, k.id + ":" + (k.storageGeneration ?? "initial"), async () => {
            const pk = await importPrivate(await keyStore.load(k.id, k.storageGeneration), k.id);
            const pub = await importPublic(k.publicJwk, k.id);
            const challenge = random(32);
            if (!await crypto.subtle.verify('Ed25519', pub, await crypto.subtle.sign('Ed25519', pk, challenge), challenge))
                fail('UNAVAILABLE', 'Key pair mismatch');
            return pk;
        });
    }
    async function issue(r: AuthReadStore, s: Session, st: State, time: number) {
        const k = await signingKey(r);
        const ttl = Math.min(p.accessTtlSec, Math.floor((Math.min(s.expiresAt, s.idleUntil) - time) / 1000));
        if (ttl < 1)
            fail('UNAUTHENTICATED');
        const base = registeredClaims(issuer, audience, st.u.id, ttl, Math.floor(time / 1000));
        const payload: JwtClaims = { ...base, sid: s.id, tenantId: st.t.id, claims: st.m.claims, userRevision: st.u.epoch, tenantRevision: st.t.epoch, grantRevision: st.m.revision, incarnation: st.m.incarnation };
        if (options.tokenData)
            payload.appData = data('tokenData', options.tokenData({ userId: st.u.id, tenantId: st.t.id, claims: Object.freeze([...st.m.claims]) }));
        return { accessToken: await signJwt(payload, await privateKey(k), k.id), expiresAt: base.exp * 1000 };
    }
    async function newSession(w: AuthWriteStore, st: State, time: number, proofAt = time): Promise<SessionTokens> {
        if (st.u.kind !== 'user')
            fail('FORBIDDEN');
        const s: Session = { id: id(), userId: st.u.id, tenantId: st.t.id, incarnation: st.m.incarnation, userEpoch: st.u.epoch, tenantEpoch: st.t.epoch, userSessionEpoch: st.u.sessionEpoch, grantSessionEpoch: st.m.sessionEpoch, createdAt: time, expiresAt: time + p.sessionTtlMs, idleUntil: time + p.idleTtlMs, revokedAt: null, proofAt };
        const rf = opaque('dfr_');
        await w.insert('sessions', s);
        await w.insert('refresh', { id: rf.keyId, sid: s.id, digest: await tag('refresh', rf.secret), expiresAt: s.expiresAt, used: false });
        return { ...await issue(w, s, st, time), refreshToken: rf.secret, sessionId: s.id, refreshExpiresAt: s.idleUntil };
    }
    async function checkedProof(r: AuthReadStore, principal: Principal, recent = false) {
        if (principal.method !== 'jwt' || !principal.sessionId)
            fail('FORBIDDEN');
        const proof = principals.get(principal);
        if (!proof?.kid || proof.exp === undefined || Math.floor(now() / 1000) >= proof.exp + p.clockToleranceSec)
            fail('UNAUTHENTICATED');
        const key = await r.get('keys', proof.kid);
        if (!key || key.state === 'revoked' || key.state === 'retired' && key.verifyUntil <= now())
            fail('UNAUTHENTICATED');
        const { s, st } = await loadSession(r, principal.sessionId, now());
        if (s.userId !== principal.subjectId || s.tenantId !== principal.tenantId || st.m.revision !== proof.revision || !principal.tokenId || await r.get('revocations', principal.tokenId))
            fail('UNAUTHENTICATED');
        if (recent && (s.proofAt < 0 || now() - s.proofAt > p.recentProofMs))
            fail('FORBIDDEN', 'Recent password authentication required');
        return { s, st };
    }
    // Principal capabilities are instance-local, unforgeable by object construction.
    const principals = new WeakMap<object, {
        exp?: number;
        kid?: string;
        revision: number;
        incarnation: string;
        userEpoch: number;
        tenantEpoch: number;
    }>();
    function requirePrincipal(principal: Principal) {
        if (!principals.has(principal))
            fail('FORBIDDEN');
    }
    async function checkPrincipal(r: AuthReadStore, principal: Principal): Promise<State> {
        requirePrincipal(principal);
        if (principal.method === 'jwt')
            return (await checkedProof(r, principal)).st;
        const proof = principals.get(principal)!, k = await r.get('apiKeys', principal.credentialId);
        if (!k || k.revokedAt !== null || k.expiresAt <= now() || k.expiresAt - k.createdAt > p.maxApiKeyTtlMs || k.subjectId !== principal.subjectId || k.tenantId !== principal.tenantId)
            fail('UNAUTHENTICATED');
        const st = await state(r, k.subjectId, k.tenantId);
        if (!matchEpoch(k, st) || st.m.revision !== proof.revision || !sameClaims(st.m.claims.filter(c => k.claims.includes(c)), principal.claims))
            fail('UNAUTHENTICATED');
        return st;
    }
    async function hydratePrincipal<T>(fn: (r: AuthReadStore) => Promise<T>): Promise<T> {
        if (closing || exclusiveMaintenance)
            fail('UNAVAILABLE');
        active++;
        try {
            return await provider.read(fn);
        }
        finally {
            if (--active === 0)
                drain();
        }
    }
    function makePrincipal(st: State, claims: string[], method: 'jwt' | 'apiKey', credentialId: string, sid?: string, jti?: string, exp?: number, kid?: string): Principal {
        const set = new Set(claims);
        const principal: Principal = freeze({
            subjectId: st.u.id, subjectKind: st.u.kind, tenantId: st.t.id,
            claims: [...set], method, credentialId, sessionId: sid, tokenId: jti,
            hasClaim: (c: string) => set.has(c), hasAllClaims: (cs: readonly string[]) => cs.every(c => set.has(c)), hasAnyClaim: (cs: readonly string[]) => cs.some(c => set.has(c)),
            getUser: () => hydratePrincipal(async (r) => { const current = await checkPrincipal(r, principal); return current.u.kind === 'user' ? publicUser(await get(r, 'users', current.u.id)) : undefined; }),
            getTenant: () => hydratePrincipal(async (r) => { const current = await checkPrincipal(r, principal); return publicTenant(await get(r, 'tenants', current.t.id)); }),
            getServiceAccount: () => hydratePrincipal(async (r) => { const current = await checkPrincipal(r, principal); return current.u.kind === 'service' ? publicService(await get(r, 'services', current.u.id)) : undefined; })
        });
        principals.set(principal, { exp, kid, revision: st.m.revision, incarnation: st.m.incarnation, userEpoch: st.u.epoch, tenantEpoch: st.t.epoch });
        return principal;
    }
    async function authenticate(input: string | Headers | Request, opts: {
        tenantId?: string;
    } = {}): Promise<Principal> {
        const auth = parseAuthorization(input);
        if (opts.tenantId !== undefined)
            identifier(opts.tenantId);
        try {
            return await provider.read(async (r) => {
                const time = now();
                if (auth.scheme === 'apiKey') {
                    const k = await r.get('apiKeys', opaqueId('dfa_', auth.token));
                    if (!k || k.revokedAt !== null || k.expiresAt <= time || k.expiresAt - k.createdAt > p.maxApiKeyTtlMs || !await verifyTag('api-key', auth.token, k.digest))
                        fail('UNAUTHENTICATED');
                    if (opts.tenantId !== undefined && opts.tenantId !== k.tenantId)
                        fail('UNAUTHENTICATED');
                    const st = await state(r, k.subjectId, k.tenantId);
                    if (st.u.kind !== k.subjectKind)
                        fail('UNAUTHENTICATED');
                    if (!matchEpoch(k, st))
                        fail('UNAUTHENTICATED');
                    const allowed = new Set(k.claims);
                    return makePrincipal(st, st.m.claims.filter(c => allowed.has(c)), 'apiKey', k.id);
                }
                let parsed;
                try {
                    parsed = prepareJwt(auth.token, p.legacyEdDSA);
                }
                catch {
                    fail('UNAUTHENTICATED');
                }
                const k = await r.get('keys', parsed.header.kid);
                if (!k || k.state === 'revoked' || k.state === 'retired' && k.verifyUntil <= time)
                    fail('UNAUTHENTICATED');
                const pub = await cached(publicCache, k.id, () => importPublic(k.publicJwk, k.id));
                const payload = await parsed.verify(pub, k.id, { issuer, audience, now: Math.floor(time / 1000), clockToleranceSec: p.clockToleranceSec, maxTtlSec: p.accessTtlSec, legacyEdDSA: p.legacyEdDSA });
                if (typeof payload.sid !== 'string' || typeof payload.tenantId !== 'string' || typeof payload.incarnation !== 'string')
                    fail('UNAUTHENTICATED');
                if (opts.tenantId !== undefined && opts.tenantId !== payload.tenantId)
                    fail('UNAUTHENTICATED');
                const { s, st } = await loadSession(r, payload.sid, time);
                if (s.userId !== payload.sub || s.tenantId !== payload.tenantId || payload.incarnation !== st.m.incarnation || payload.userRevision !== st.u.epoch || payload.tenantRevision !== st.t.epoch || payload.grantRevision !== st.m.revision || !sameClaims(payload.claims, st.m.claims) || await r.get('revocations', payload.jti))
                    fail('UNAUTHENTICATED');
                return makePrincipal(st, st.m.claims, 'jwt', payload.jti, s.id, payload.jti, payload.exp, k.id);
            });
        }
        catch (e) {
            if (e instanceof AuthError && ['INVALID_INPUT', 'UNAUTHENTICATED'].includes(e.code))
                fail('UNAUTHENTICATED');
            throw e;
        }
    }
    // Initialize persistent configuration; never replace a missing or corrupt active key.
    await provider.init();
    let meta = await provider.read(r => r.get('meta', 'authority'));
    if (!meta) {
        const pair = await genEd25519Pair();
        await keyStore.save(pair);
        meta = await tx(async (w) => {
            const previous = await w.get('meta', 'authority');
            if (previous)
                return previous;
            const m = { id: 'authority', issuer, audience, schemaHash, activeKid: pair.kid, format: 2 as const, configHash };
            await w.insert('keys', { id: pair.kid, publicJwk: pair.publicJwk, state: 'active', createdAt: now(), verifyUntil: Number.MAX_SAFE_INTEGER, expiresAt: Number.MAX_SAFE_INTEGER });
            await w.insert('meta', m);
            if (defaultEnabled)
                await w.insert('tenants', { id: 'default', status: 'active', createdAt: now(), updatedAt: now(), epoch: 1, data: defaultData });
            return m;
        });
    }
    if (meta.format !== 2 || meta.issuer !== issuer || meta.audience !== audience)
        fail('UNAVAILABLE', 'Authority format or identity mismatch');
    if (meta.configHash !== configHash) {
        if (options.migrateFrom !== meta.configHash)
            fail('UNAVAILABLE', 'Authority configuration mismatch; explicit migration required');
        await tx(async (w) => {
            const m = await get(w, 'meta', 'authority');
            if (m.configHash !== options.migrateFrom)
                fail('CONFLICT', 'Configuration changed');
            if (m.schemaHash !== schemaHash) {
                for (const [table, kind] of [['users', 'user'], ['tenants', 'tenant'], ['services', 'service']] as const) {
                    let after: string | undefined;
                    for (;;) {
                        const rows = await w.list(table, { limit: 100, after });
                        for (const row of rows) {
                            const updated = data(kind, options.migrateData ? options.migrateData(kind, dataCopy(row.data)) : row.data);
                            if (JSON.stringify(updated) !== JSON.stringify(row.data))
                                await w.put(table, { ...row, data: updated } as never);
                        }
                        if (rows.length < 100)
                            break;
                        after = rows.at(-1)!.id;
                    }
                }
            }
            if (defaultEnabled && !await w.get('tenants', 'default'))
                await w.insert('tenants', { id: 'default', status: 'active', createdAt: now(), updatedAt: now(), epoch: 1, data: defaultData });
            m.schemaHash = schemaHash;
            m.configHash = configHash;
            await w.put('meta', m);
        });
    }
    initialized = true;
    await provider.read(async (r) => {
        await privateKey(await signingKey(r));
        if (defaultEnabled) {
            const t = await get(r, 'tenants', 'default');
            data('tenant', t.data);
        }
    });
    const ctx: OperationsContext = { provider, keyStore, options, configHash, p, now, hasher, dummyHash, defaultEnabled, autoJoin, data, read, tx, get, state, matchEpoch, sessionValid, emit, throttle, signingKey, privateCache, publicCache, issue, newSession, checkedProof, requirePrincipal, authenticate, async withExclusive(fn) { if (active !== 1 || exclusiveMaintenance)
            fail('CONFLICT', 'Other authority operations are active'); exclusiveMaintenance = true; try {
            return await fn();
        }
        finally {
            exclusiveMaintenance = false;
        } } };
    const api = { ...createAdminOperations(ctx), ...createIdentityOperations(ctx), ...createSessionsOperations(ctx), ...createApiKeysOperations(ctx), ...createChallengesOperations(ctx), ...createLifecycleOperations(ctx) };
    // Only public calls participate in draining. Internal methods never call the wrapper recursively.
    type Api = typeof api;
    const exposed = {} as Api;
    for (const k of Object.keys(api) as (keyof Api)[]) {
        const fn = api[k] as (...args: any[]) => Promise<any>;
        (exposed as any)[k] = async (...args: any[]) => {
            if (exclusiveMaintenance)
                fail('UNAVAILABLE', 'Exclusive maintenance in progress');
            if (closing)
                fail('UNAVAILABLE', 'Authority closed');
            active++;
            const start = performance.now();
            let outcome: 'ok' | 'error' = 'ok', code: string | undefined;
            try {
                return await fn(...args);
            }
            catch (e) {
                outcome = 'error';
                code = e instanceof AuthError ? e.code : 'UNAVAILABLE';
                throw e;
            }
            finally {
                try {
                    options.telemetry?.({ operation: String(k), outcome, durationMs: performance.now() - start, code });
                }
                catch { }
                if (--active === 0)
                    drain();
            }
        };
    }
    return Object.freeze({
        ...exposed, close() {
            if (!closePromise) {
                closing = true;
                closePromise = (async () => {
                    if (active)
                        await new Promise<void>(r => {
                            drain = r;
                        });
                    publicCache.clear();
                    privateCache.clear();
                    if (options.ownProvider)
                        await provider.close();
                })();
            }
            return closePromise;
        }
    });
}
type BaseAuth = Awaited<ReturnType<typeof createAuthority>>;
export type TypedPrincipal<S extends SchemaSet> = Omit<Principal, 'getUser' | 'getTenant' | 'getServiceAccount'> & {
    getUser(): Promise<import('./records.js').User<SchemaData<S, 'user'>> | undefined>;
    getTenant(): Promise<import('./records.js').Tenant<SchemaData<S, 'tenant'>>>;
    getServiceAccount(): Promise<import('./records.js').ServiceAccount<SchemaData<S, 'service'>> | undefined>;
};
type TypedMethods<S extends SchemaSet> = {
    getUser(id: string, guard?: AdminGuard): Promise<import('./records.js').User<SchemaData<S, 'user'>> | undefined>;
    getUserByEmail(email: string): Promise<import('./records.js').User<SchemaData<S, 'user'>> | undefined>;
    createUser(input: Omit<Parameters<BaseAuth['createUser']>[0], 'data'> & {
        data?: SchemaData<S, 'user'>;
    }, guard?: AdminGuard): Promise<import('./records.js').User<SchemaData<S, 'user'>>>;
    updateUser(id: string, patch: Omit<Parameters<BaseAuth['updateUser']>[1], 'data'> & {
        data?: SchemaData<S, 'user'>;
    }, guard?: AdminGuard): Promise<import('./records.js').User<SchemaData<S, 'user'>>>;
    listUsers(page?: ListOptions, guard?: AdminGuard): Promise<import('./records.js').User<SchemaData<S, 'user'>>[]>;
    getTenant(id?: string, guard?: AdminGuard): Promise<import('./records.js').Tenant<SchemaData<S, 'tenant'>> | undefined>;
    createTenant(input: Omit<Parameters<BaseAuth['createTenant']>[0], 'data'> & {
        data?: SchemaData<S, 'tenant'>;
    }, guard?: AdminGuard): Promise<import('./records.js').Tenant<SchemaData<S, 'tenant'>>>;
    updateTenant(id: string, patch: Omit<Parameters<BaseAuth['updateTenant']>[1], 'data'> & {
        data?: SchemaData<S, 'tenant'>;
    }, guard?: AdminGuard): Promise<import('./records.js').Tenant<SchemaData<S, 'tenant'>>>;
    listTenants(page?: ListOptions, guard?: AdminGuard): Promise<import('./records.js').Tenant<SchemaData<S, 'tenant'>>[]>;
    getServiceAccount(id: string, guard?: AdminGuard): Promise<import('./records.js').ServiceAccount<SchemaData<S, 'service'>> | undefined>;
    createServiceAccount(input: Omit<Parameters<BaseAuth['createServiceAccount']>[0], 'data'> & {
        data?: SchemaData<S, 'service'>;
    }, guard?: AdminGuard): Promise<import('./records.js').ServiceAccount<SchemaData<S, 'service'>>>;
    updateServiceAccount(id: string, patch: Omit<Parameters<BaseAuth['updateServiceAccount']>[1], 'data'> & {
        data?: SchemaData<S, 'service'>;
    }, guard?: AdminGuard): Promise<import('./records.js').ServiceAccount<SchemaData<S, 'service'>>>;
    listServiceAccounts(tenantId: string, page?: ListOptions, guard?: AdminGuard): Promise<import('./records.js').ServiceAccount<SchemaData<S, 'service'>>[]>;
    authenticate(...args: Parameters<BaseAuth['authenticate']>): Promise<TypedPrincipal<S>>;
    requireAuth(...args: Parameters<BaseAuth['requireAuth']>): Promise<TypedPrincipal<S>>;
    requestRegistration(input: Omit<Parameters<BaseAuth['requestRegistration']>[0], 'data'> & {data?: SchemaData<S, 'user'>}): Promise<void>;
    acceptInvitation(input: Omit<Parameters<BaseAuth['acceptInvitation']>[0], 'data'> & {data?: SchemaData<S, 'user'>}): Promise<{userId:string;tenantId:string}>;
    confirmRegistration(input: Parameters<BaseAuth['confirmRegistration']>[0]): Promise<import('./records.js').User<SchemaData<S, 'user'>>>;
};
export type Auth<S extends SchemaSet = SchemaSet> = Omit<BaseAuth, keyof TypedMethods<S>> & TypedMethods<S>;
/** Schema-driven types project the validated JSON records; validation is always enforced at runtime. */
export async function createAuth<const S extends SchemaSet = SchemaSet>(options: AuthOptions<S>): Promise<Auth<S>> {
    return await createAuthority(options) as Auth<S>;
}
