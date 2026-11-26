/** Several isolated authorities behind one Fetch endpoint, for a service that hosts authentication for its apps.
 * The host owns no listener: mount `plugin()` on a server, or call `fetch` from any Fetch-native router. */
import { join } from 'node:path';
import type { AdminOperation,Auth,AuthOptions,Principal } from './auth.js';
import type { MasterKeyRing } from './keys.js';
import type { SchemaSet } from './schema.js';
import { createAuthHandler,type HandlerOptions } from './serve.js';
import { createAuth } from './server.js';
import { AuthError,fail,string,tag,utf8,verifyTag,type ErrorCode } from './util.js';

/** The `defuss-auth/server` options without storage and keys, which the host supplies. Declared from AuthOptions, so
 * these types need no defuss-db or defuss-storage declarations. VERIFIED: package-e2e compiles a consumer without them. */
export interface HostedAppOptions<S extends SchemaSet = SchemaSet> extends Omit<AuthOptions<S>, 'provider' | 'keyStore' | 'passwordHasher' | 'ownProvider'> {
    /** Defaults: defuss-db in the app's directory, encrypted key files beside it, Argon2id. */
    provider?: AuthOptions['provider'];
    keyStore?: AuthOptions['keyStore'];
    passwordHasher?: AuthOptions['passwordHasher'];
    /** Routes of this app. `prefix` is the path the app's own proxy mounts, so the refresh cookie's Path matches what the browser sees. */
    http?: Omit<HandlerOptions, 'ownAuth' | 'rateKey'>;
    /** Trusted proxies in front of the app's own listener, such as a TLS terminator: X-Forwarded-For entries to skip from the right. Default 0. */
    forwardedHops?: number;
}
export interface AuthHostOptions {
    /** Root directory; each app keeps its database and key files in `<directory>/<app>`. */
    directory: string;
    /** 256-bit host key, or a keyring for master-key rotation. Each app gets its own key derived with HKDF-SHA-256. */
    masterKey?: Uint8Array;
    keyRing?: MasterKeyRing;
    /** Mount point of the apps: `<basePath>/<app>/<path the app's handler serves>`. Default `/apps`. */
    basePath?: string;
    /** The field and secret an app's proxy sends. Without it, the routes are public and X-Forwarded-For is never trusted. */
    credential?: { header: string; secret: string };
}
/** What a resource server needs about a caller. Plain data, so it can cross RPC; only meaningful for the one request it answered. */
export interface HostPrincipal {
    app: string;
    subjectId: string;
    subjectKind: 'user' | 'service';
    tenantId: string;
    claims: string[];
    method: 'jwt' | 'apiKey';
    credentialId: string;
    sessionId: string | null;
}
export interface AuthHost {
    /** Open an app's authority. Its name is lowercase `[a-z0-9_-]`, 1 to 64 characters, starting with a letter or digit. */
    open<S extends SchemaSet = SchemaSet>(app: string, options: HostedAppOptions<S>): Promise<Auth<S>>;
    /** The open authority, for trusted server-side operations such as createUser. */
    get(app: string): Auth | undefined;
    apps(): string[];
    /** Close and forget one app; its files stay. */
    close(app: string): Promise<boolean>;
    /** Verify a credential live (revocation, grant changes) and project it. Pass the tenant the request acts in. */
    authenticate(app: string, authorization: string, options?: { tenantId?: string; claims?: string[]; anyClaims?: string[] }): Promise<HostPrincipal>;
    /** Run `maintain` in every app: signing-key rotation and cleanup. One app's failure leaves the others running. */
    maintain(limit?: number): Promise<Record<string, unknown>>;
    fetch(request: Request): Promise<Response>;
    /** A route-declaring plugin shape that defuss-serve accepts; `close` closes every app. */
    plugin(name?: string): { name: string; routes: readonly { path: string; prefix: boolean }[]; fetch(request: Request): Promise<Response>; close(): Promise<void> };
    closeAll(): Promise<void>;
}
const status: Record<ErrorCode, number> = { INVALID_INPUT: 400, UNAUTHENTICATED: 401, FORBIDDEN: 403, NOT_FOUND: 404, CONFLICT: 409, SCHEMA: 422, RATE_LIMIT: 429, UNAVAILABLE: 503 };
const json = (error: ErrorCode) => new Response(JSON.stringify({ error }), { status: status[error], headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
// Lowercase only: on a case-insensitive volume, `App` and `app` would share one directory and one database.
const appName = (v: unknown) => { const s = string(v, 64); if (!/^[a-z0-9][a-z0-9_-]*$/.test(s)) fail('INVALID_INPUT', 'Invalid app name'); return s; };
// Fields the proxy credential must not reuse: the handler reads them, or the transport owns them.
const reserved = new Set(['authorization', 'cookie', 'origin', 'host', 'content-type', 'content-length', 'x-defuss-csrf', 'forwarded', 'x-real-ip']);
async function derive(key: Uint8Array, app: string) {
    if (!(key instanceof Uint8Array) || key.length !== 32) fail('INVALID_INPUT', 'Expected 256-bit master key');
    const base = await crypto.subtle.importKey('raw', key.slice(), 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: utf8('defuss-auth/host/v1'), info: utf8(app) }, base, 256));
}
/** The client address a trusted app proxy observed: the X-Forwarded-For entry `hops` places left of the right end. */
function forwardedClient(request: Request, hops: number) {
    const chain = (request.headers.get('x-forwarded-for') ?? '').split(',').map(x => x.trim()).filter(Boolean);
    const client = chain[chain.length - 1 - hops];
    return client && client.length <= 64 && /^[0-9A-Fa-f:.]+$/.test(client) ? 'ip:' + client : undefined;
}
/** Tenant administrators: principals holding `claim` in the tenant an operation targets. `prepareAdmin` passes the
 * target's actual tenant, read in the same snapshot it rechecks, so a forged `tenantId` field cannot widen it.
 * Global user routes name no tenant and are refused, and so are tenant routes, which would let an administrator
 * delete their own tenant; keep both for trusted server-side calls. */
export function tenantAdmin(claim: string): NonNullable<HandlerOptions['authorizeAdmin']> {
    const required = string(claim, 128);
    return (principal: Principal, operation: AdminOperation) => !operation.resource.startsWith('tenants') && operation.tenantId !== undefined && operation.tenantId === principal.tenantId && principal.hasClaim(required);
}
export async function createAuthHost(options: AuthHostOptions): Promise<AuthHost> {
    const directory = string(options.directory, 4096), base = options.basePath ?? '/apps';
    if (!/^\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*$/.test(base) || base.split('/').some(x => x === '.' || x === '..')) fail('INVALID_INPUT', 'Invalid basePath');
    if (options.masterKey && options.keyRing) fail('INVALID_INPUT', 'Supply one master key or keyring');
    let credential: { header: string; digest: string } | undefined;
    if (options.credential) {
        const header = string(options.credential.header, 64).toLowerCase(), secret = string(options.credential.secret, 1024);
        if (!/^[a-z0-9-]+$/.test(header) || reserved.has(header) || header.startsWith('x-forwarded-')) fail('INVALID_INPUT', 'Invalid credential header');
        if (secret.length < 16) fail('INVALID_INPUT', 'Credential secret too short');
        credential = { header, digest: await tag('host-credential', secret) };
    }
    const apps = new Map<string, { auth: Auth; handler: ReturnType<typeof createAuthHandler> }>();
    const opening = new Set<string>();
    async function open<S extends SchemaSet>(name: string, app: HostedAppOptions<S>): Promise<Auth<S>> {
        const id = appName(name), hops = app.forwardedHops ?? 0;
        if (!Number.isSafeInteger(hops) || hops < 0 || hops > 8) fail('INVALID_INPUT', 'Invalid forwardedHops');
        if (apps.has(id) || opening.has(id)) fail('CONFLICT', 'App already open');
        opening.add(id);
        try {
            const { http, forwardedHops: _hops, ...rest } = app;
            const keys = app.keyStore ? {} : options.keyRing
                ? { keyRing: { activeVersion: options.keyRing.activeVersion, keys: Object.fromEntries(await Promise.all(Object.entries(options.keyRing.keys).map(async ([v, k]) => [v, await derive(k, id)] as const))) } }
                : options.masterKey ? { encryptionKey: await derive(options.masterKey, id) } : fail('INVALID_INPUT', 'Host needs a master key or keyring');
            const auth = await createAuth<S>({ ...rest, ...keys, storage: { directory: join(directory, id) } });
            try {
                // A rate key only from a request that carried the proxy credential: anyone else could choose the field.
                const handler = createAuthHandler(auth, { ...http, rateKey: credential ? r => forwardedClient(r, hops) : undefined });
                apps.set(id, { auth: auth as unknown as Auth, handler });
            } catch (e) { await auth.close(); throw e; }
            return auth;
        } finally { opening.delete(id); }
    }
    async function fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        if (!url.pathname.startsWith(base + '/')) return json('NOT_FOUND');
        // The credential first, so a caller without it cannot tell which app names exist.
        if (credential) {
            const presented = request.headers.get(credential.header);
            if (!presented || presented.length > 1024 || !await verifyTag('host-credential', presented, credential.digest)) return json('FORBIDDEN');
        }
        const rest = url.pathname.slice(base.length + 1), slash = rest.indexOf('/');
        const app = slash > 0 ? apps.get(rest.slice(0, slash)) : undefined;
        if (!app) return json('NOT_FOUND');
        const headers = new Headers(request.headers);
        if (credential) headers.delete(credential.header);
        url.pathname = rest.slice(slash);
        const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body ?? undefined;
        return app.handler.fetch(new Request(url, { method: request.method, headers, body, signal: request.signal, ...(body ? { duplex: 'half' } : {}) } as RequestInit));
    }
    async function close(name: string) {
        const app = apps.get(name);
        if (!app) return false;
        apps.delete(name); await app.auth.close(); return true;
    }
    async function closeAll() {
        const all = [...apps.keys()];
        const results = await Promise.allSettled(all.map(close));
        const failed = results.filter(r => r.status === 'rejected');
        if (failed.length) throw new AggregateError(failed.map(r => (r as PromiseRejectedResult).reason), 'Closing apps failed');
    }
    return Object.freeze({
        open, fetch, close, closeAll,
        get: (name: string) => apps.get(name)?.auth,
        apps: () => [...apps.keys()],
        async authenticate(name: string, authorization: string, opts: { tenantId?: string; claims?: string[]; anyClaims?: string[] } = {}): Promise<HostPrincipal> {
            const app = apps.get(name) ?? fail('NOT_FOUND', 'Unknown app');
            // RPC arguments arrive untyped: a claims value that is no string list would otherwise fail as a TypeError.
            const list = (v: unknown) => v === undefined ? undefined : Array.isArray(v) && v.length <= 256 && v.every(c => typeof c === 'string') ? v as string[] : fail('INVALID_INPUT', 'Invalid claims');
            const p = await app.auth.requireAuth(string(authorization, 8192), { tenantId: opts.tenantId, claims: list(opts.claims), anyClaims: list(opts.anyClaims) });
            return { app: name, subjectId: p.subjectId, subjectKind: p.subjectKind, tenantId: p.tenantId, claims: [...p.claims], method: p.method, credentialId: p.credentialId, sessionId: p.sessionId ?? null };
        },
        async maintain(limit?: number) {
            const out: Record<string, unknown> = {};
            await Promise.all([...apps].map(async ([name, app]) => {
                try { out[name] = await app.auth.maintain(limit); }
                catch (e) { out[name] = { error: e instanceof AuthError ? e.code : 'UNAVAILABLE' }; }
            }));
            return out;
        },
        plugin: (name = 'defuss-auth-host') => Object.freeze({ name, routes: Object.freeze([Object.freeze({ path: base, prefix: true })]), fetch, close: closeAll }),
    });
}
