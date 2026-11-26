/** Fetch-native transport. The authority does not start or own an HTTP listener. */
import type { AdminOperation,Auth,Principal,SessionTokens } from './auth.js';
import type { ListOptions } from './providers.js';
import type { SchemaSet } from './schema.js';
import { SchemaValidationError } from './schema.js';
import { AuthError,fail,object,parseJson,string,type ErrorCode } from './util.js';
export interface ServePlugin {
    readonly name: string;
    matches(request: Request): boolean;
    fetch(request: Request): Promise<Response>;
    close?(): Promise<void>;
}
export interface HandlerOptions {
    prefix?: string;
    jwksPath?: string;
    mode?: 'cookie' | 'token';
    /** Explicit trusted web origins. Cookie mode requires at least one origin. */
    allowedOrigins?: readonly string[];
    cookieName?: string;
    maxBodyBytes?: number;
    /** Trusted connection metadata only; never blindly trust X-Forwarded-For. */
    rateKey?: (request: Request) => string | undefined;
    authorizeAdmin?: (principal: Principal, operation: AdminOperation & {target?:unknown}) => boolean | Promise<boolean>;
    /** Explicit opt-in to application profile fields. Default /me is identity metadata only. */
    projectPrincipal?: (principal: Principal) => unknown | Promise<unknown>;
    ownAuth?: boolean;
    onError?: (code: ErrorCode) => void;
}
const status: Record<ErrorCode, number> = { INVALID_INPUT: 400, UNAUTHENTICATED: 401, FORBIDDEN: 403, NOT_FOUND: 404, CONFLICT: 409, SCHEMA: 422, RATE_LIMIT: 429, UNAVAILABLE: 503 };
const json = (value: unknown, code = 200) => new Response(JSON.stringify(value), {
    status: code, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
});
const empty = () => new Response(null, {
    status: 204, headers: { 'cache-control': 'no-store' }
});
const routePath = (p: string) => {
    if (!/^\/(?:[A-Za-z0-9._~-]+\/?)+$/.test(p) || p.endsWith('/') || p.split('/').some(x => x === '.' || x === '..'))
        fail('INVALID_INPUT', 'Invalid route prefix');
    return p;
};
function page(url: URL): ListOptions {
    const raw = url.searchParams.get('limit'), after = url.searchParams.get('after');
    return { limit: raw === null ? undefined : Number(raw), after: after ?? undefined };
}
function decodePath(path: string) {
    if (path.includes('%') || path.includes('\\') || path.includes('//') || path.endsWith('/'))
        fail('NOT_FOUND');
    return path.split('/').slice(1);
}
async function body(request: Request, max: number): Promise<Record<string, any>> {
    if (!request.body)
        return {};
    // VERIFIED: Node adapters attach an empty stream to every non-GET request (http-e2e), so only a payload needs the JSON type.
    const type = request.headers.get('content-type');
    if (type !== null && !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type))
        fail('INVALID_INPUT', 'Expected application/json');
    const length = request.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > max))
        fail('INVALID_INPUT');
    const reader = request.body.getReader();
    let size = 0;
    const chunks: Uint8Array[] = [];
    try {
        for (;;) {
            const r = await reader.read();
            if (r.done)
                break;
            size += r.value.length;
            if (size > max) {
                await reader.cancel();
                fail('INVALID_INPUT', 'Body too large');
            }
            chunks.push(r.value);
        }
    }
    finally {
        reader.releaseLock();
    }
    if (type === null) {
        if (size)
            fail('INVALID_INPUT', 'Expected application/json');
        return {};
    }
    const a = new Uint8Array(size);
    let offset = 0;
    for (const c of chunks) {
        a.set(c, offset);
        offset += c.length;
    }
    let parsed;
    try {
        parsed = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(a), max);
    }
    catch {
        fail('INVALID_INPUT', 'Invalid JSON body');
    }
    if (!object(parsed))
        fail('INVALID_INPUT', 'Expected JSON object');
    return parsed;
}
function present<T>(value: T | undefined): T {
    if (value === undefined)
        fail('NOT_FOUND');
    return value;
}
function publicPrincipal(p: Principal) {
    return {subjectId:p.subjectId,subjectKind:p.subjectKind,tenantId:p.tenantId,claims:p.claims,method:p.method,sessionId:p.sessionId};
}
export function createAuthHandler<S extends SchemaSet>(typedAuth: Auth<S>, options: HandlerOptions = {}) {
    const auth=typedAuth as unknown as Auth;
    const prefix = routePath(options.prefix ?? '/auth'), jwksPath = routePath(options.jwksPath ?? '/.well-known/jwks.json'), mode = options.mode ?? 'cookie', max = options.maxBodyBytes ?? 65536;
    if (!['cookie', 'token'].includes(mode) || !Number.isSafeInteger(max) || max < 1024 || max > 1048576)
        fail('INVALID_INPUT');
    const origins = new Set((options.allowedOrigins ?? []).map(o => {
        const u = new URL(o);
        if (u.origin !== o || !['https:', 'http:'].includes(u.protocol) || u.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname))
            fail('INVALID_INPUT', 'Invalid trusted origin');
        return o;
    }));
    if (mode === 'cookie' && !origins.size)
        fail('INVALID_INPUT', 'Cookie mode requires allowedOrigins');
    const cookieName = options.cookieName ?? '__Secure-defuss_refresh';
    if (!/^__Secure-[a-zA-Z0-9_-]+$/.test(cookieName))
        fail('INVALID_INPUT');
    const reserved = (path: string) => path === jwksPath || path === prefix || path.startsWith(prefix + '/');
    const matches = (r: Request) => {
        const path = new URL(r.url).pathname;
        if (reserved(path))
            return true;
        try {
            return reserved(decodeURIComponent(path));
        }
        catch {
            return false;
        }
    };
    const routes: Record<string, string[]> = {
        '/login': ['POST'], '/login/email/request':['POST'], '/login/email/confirm':['POST'], '/register/request':['POST'], '/register/confirm':['POST'], '/invitation/accept':['POST'], '/password/step-up':['POST'], '/refresh': ['POST'], '/logout': ['POST'], '/logout-all': ['POST'], '/token/revoke': ['POST'], '/me': ['GET'], '/sessions': ['GET'], '/tenants': ['GET'], '/tenant/switch': ['POST'], '/password/change': ['POST'], '/password/reset/request': ['POST'], '/password/reset/confirm': ['POST'], '/email/verify/request': ['POST'], '/email/verify/confirm': ['POST'], '/api-keys': ['GET', 'POST']
    };
    function methods(path: string): string[] | undefined {
        if (Object.hasOwn(routes, path))
            return routes[path];
        if (/^\/sessions\/[A-Za-z0-9_-]+$/.test(path))
            return ['DELETE'];
        if (/^\/api-keys\/[A-Za-z0-9_-]+$/.test(path))
            return ['GET', 'PATCH', 'DELETE'];
        if (/^\/api-keys\/[A-Za-z0-9_-]+\/rotate$/.test(path))
            return ['POST'];
        if (options.authorizeAdmin) {
            if(path==='/admin/invitations')return ['POST'];
            if(/^\/admin\/invitations\/[A-Za-z0-9_-]+$/.test(path))return ['DELETE'];
            if(/^\/admin\/services\/[A-Za-z0-9_-]+\/api-keys$/.test(path))return ['GET','POST'];
            if(/^\/admin\/services\/[A-Za-z0-9_-]+\/api-keys\/[A-Za-z0-9_-]+$/.test(path))return ['GET','PATCH','DELETE'];
            if(/^\/admin\/services\/[A-Za-z0-9_-]+\/api-keys\/[A-Za-z0-9_-]+\/rotate$/.test(path))return ['POST'];
            if (/^\/admin\/(users|tenants|services)$/.test(path))
                return ['GET', 'POST'];
            if (/^\/admin\/(users|tenants|services)\/[A-Za-z0-9_-]+$/.test(path))
                return ['GET', 'PATCH', 'DELETE'];
            if (/^\/admin\/(users|services)\/[A-Za-z0-9_-]+\/claims$/.test(path))
                return ['GET'];
            if (/^\/admin\/(users|services)\/[A-Za-z0-9_-]+\/claims\/[A-Za-z0-9_-]+$/.test(path))
                return ['GET', 'PUT', 'DELETE'];
        }
        return undefined;
    }
    function cookie(request: Request) {
        const h = request.headers.get('cookie') ?? '';
        if (h.length > 16384)
            fail('INVALID_INPUT');
        const all = h.split(';').map(c => c.trim()).filter(c => c.startsWith(cookieName + '='));
        if (all.length > 1)
            fail('INVALID_INPUT', 'Duplicate refresh cookie');
        return all[0]?.slice(cookieName.length + 1);
    }
    function setCookie(response: Response, token: string, ttl: number) {
        response.headers.append('set-cookie', `${cookieName}=${token}; Path=${prefix}; Max-Age=${Math.max(0, Math.floor(ttl))}; HttpOnly; Secure; SameSite=Strict`);
        return response;
    }
    function tokens(t: SessionTokens) {
        if (mode === 'token')
            return json(t);
        const { refreshToken, refreshExpiresAt, ...safe } = t;
        return setCookie(json({ ...safe, refreshExpiresAt }), refreshToken, (refreshExpiresAt - Date.now()) / 1000);
    }
    function cors(response: Response, origin: string | null) {
        if (origin && origins.has(origin)) {
            response.headers.set('access-control-allow-origin', origin);
            response.headers.set('vary', 'Origin');
            if (mode === 'cookie')
                response.headers.set('access-control-allow-credentials', 'true');
        }
        return response;
    }
    async function handle(request: Request): Promise<Response> {
        const url = new URL(request.url), origin = request.headers.get('origin'), method = request.method.toUpperCase();
        try {
            if (!matches(request) || !reserved(url.pathname) || url.pathname.includes('%'))
                return json({ error: 'NOT_FOUND' }, 404);
            if (origin && !origins.has(origin))
                fail('FORBIDDEN');
            if (method === 'OPTIONS') {
                if (!origin || !origins.has(origin))
                    fail('FORBIDDEN');
                const res = empty();
                res.headers.set('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
                res.headers.set('access-control-allow-headers', 'authorization, content-type, x-defuss-csrf');
                res.headers.set('access-control-max-age', '600');
                return cors(res, origin);
            }
            if (url.pathname === jwksPath) {
                if (method !== 'GET')
                    return json({ error: 'METHOD_NOT_ALLOWED' }, 405);
                const res = json(await auth.jwks());
                res.headers.set('cache-control', 'public, max-age=60');
                return cors(res, origin);
            }
            const mutate = method !== 'GET' && method !== 'HEAD';
            if (mutate && mode === 'cookie' && (!origin || !origins.has(origin) || request.headers.get('x-defuss-csrf') !== '1'))
                fail('FORBIDDEN', 'CSRF');
            const path = url.pathname.slice(prefix.length);
            const allowed = methods(path);
            if (!allowed)
                fail('NOT_FOUND');
            if (!allowed.includes(method)) {
                const res = json({ error: 'METHOD_NOT_ALLOWED' }, 405);
                res.headers.set('allow', allowed.join(', '));
                return cors(res, origin);
            }
            const seg = decodePath(path);
            const [a,b,c,d,e,f]=seg;
            const input = mutate ? await body(request, max) : {};
            const principal = () => auth.authenticate(request);
            const refresh = () => mode === 'cookie' ? cookie(request) : input.refreshToken;
            const who = (p: Principal) => ({ subjectId: p.subjectId, tenantId: p.tenantId });
            const rate = () => {
                const x = options.rateKey?.(request);
                return x === undefined ? undefined : string(x, 256);
            };
            let res: Response;
            if (method === 'POST' && path === '/login')
                res = tokens(await auth.login({ email: input.email, password: input.password, tenantId: input.tenantId, rateKey: rate() }));
            else if(method==='POST'&&path==='/login/email/request'){await auth.requestPasswordlessLogin({email:input.email,tenantId:input.tenantId,rateKey:rate()});res=empty();}
            else if(method==='POST'&&path==='/login/email/confirm')res=tokens(await auth.confirmPasswordlessLogin(input.token));
            else if(method==='POST'&&path==='/register/request'){await auth.requestRegistration({email:input.email,data:input.data,rateKey:rate()});res=empty();}
            else if(method==='POST'&&path==='/register/confirm'){await auth.confirmRegistration({token:input.token,password:input.password});res=empty();}
            else if(method==='POST'&&path==='/invitation/accept'){await auth.acceptInvitation({token:input.token,password:input.password,data:input.data});res=empty();}
            else if(method==='POST'&&path==='/password/step-up')res=tokens(await auth.stepUp(await principal(),input.password));
            else if (method === 'POST' && path === '/refresh')
                res = tokens(await auth.refresh(refresh()));
            else if (method === 'POST' && path === '/logout') {
                const token = refresh();
                if (token)
                    await auth.logoutRefresh(token);
                else if (request.headers.has('authorization'))
                    await auth.logout(await principal());
                res = mode === 'cookie' ? setCookie(empty(), '', 0) : empty();
            }
            else if (method === 'POST' && path === '/logout-all') {
                await auth.logoutAll(await principal(), input.scope);
                res = mode === 'cookie' ? setCookie(empty(), '', 0) : empty();
            }
            else if (method === 'POST' && path === '/token/revoke') {
                await auth.revokeToken(input.token, await principal());
                res = empty();
            }
            else if (method === 'GET' && path === '/me')
                {const p=await principal();res=json({...publicPrincipal(p),...(options.projectPrincipal?{profile:await options.projectPrincipal(p)}:{})});}
            else if (method === 'GET' && path === '/sessions')
                res = json(await auth.listSessions(await principal(), page(url)));
            else if (method === 'DELETE' && a === 'sessions' && b && seg.length === 2) {
                await auth.revokeSession(await principal(), b);
                res = empty();
            }
            else if (method === 'GET' && path === '/tenants') {
                const p = await principal();
                if (p.method !== 'jwt')
                    fail('FORBIDDEN');
                res = json(await auth.listTenantIds(p.subjectId, page(url)));
            }
            else if (method === 'POST' && path === '/tenant/switch')
                res = tokens(await auth.switchTenant(await principal(), input.tenantId));
            else if (method === 'POST' && path === '/password/change') {
                await auth.changePassword(await principal(), input.currentPassword, input.newPassword);
                res = mode === 'cookie' ? setCookie(empty(), '', 0) : empty();
            }
            else if (method === 'POST' && path === '/password/reset/request') {
                await auth.requestPasswordReset(input.email, rate());
                res = empty();
            }
            else if (method === 'POST' && path === '/password/reset/confirm') {
                await auth.resetPassword(input.token, input.newPassword);
                res = empty();
            }
            else if (method === 'POST' && path === '/email/verify/request') {
                await auth.requestEmailVerification(input.email, rate());
                res = empty();
            }
            else if (method === 'POST' && path === '/email/verify/confirm') {
                await auth.verifyEmail(input.token);
                res = empty();
            }
            else if (a === 'api-keys' && seg.length <= 3) {
                const p = await principal();
                if (p.method !== 'jwt')
                    fail('FORBIDDEN');
                if (!b && method === 'POST')
                    res = json(await auth.createApiKey({ ...who(p), name: input.name, claims: input.claims, expiresAt: input.expiresAt }, p), 201);
                else if (!b && method === 'GET')
                    res = json(await auth.listApiKeys({ ...who(p), ...page(url) }, p));
                else if (b && !c && method === 'GET')
                    res = json(present(await auth.getApiKey(b, p)));
                else if (b && !c && method === 'PATCH')
                    res = json(await auth.updateApiKey(b, { name: input.name, claims: input.claims }, p));
                else if (b && !c && method === 'DELETE') {
                    await auth.revokeApiKey(b, p);
                    res = empty();
                }
                else if (b && c === 'rotate' && method === 'POST')
                    res = json(await auth.rotateApiKey(b, p), 201);
                else
                    fail('NOT_FOUND');
            }
            else if (a === 'admin' && options.authorizeAdmin) {
                const p = await principal();
                if(p.method!=='jwt')fail('FORBIDDEN');
                const op:AdminOperation={method,resource:[b,d].filter(Boolean).join('/'),keyId:d==='api-keys'?e:undefined,id:c??(b==='tenants'&&typeof input.id==='string'?input.id:undefined),tenantId:b==='tenants'?c??input.id:d==='claims'?e:b==='services'||b==='invitations'?input.tenantId??url.searchParams.get('tenantId')??(b==='services'&&!c?'default':undefined):undefined,body:Object.freeze(Object.fromEntries(Object.entries(input).filter(([k])=>!['password','currentPassword','newPassword','token','refreshToken'].includes(k))))};
                const guard=await auth.prepareAdmin(p,op,options.authorizeAdmin);
                // Handlers act on op.tenantId, the tenant the policy authorized, never on a separately read request field.
                // VERIFIED: reading input.tenantId let a tenant admin create a service account in `default` (v02 test).
                if(b==='invitations'&&method==='POST'){res=json(await auth.inviteToTenant({email:input.email,tenantId:op.tenantId!,claims:input.claims},guard),201);}
                else if (b === 'users' && !d) {
                    if (!c && method === 'POST')
                        res = json(await auth.createUser({ email: input.email, password: input.password, data: input.data, joinDefault: input.joinDefault },guard), 201);
                    else if (!c && method === 'GET')
                        res = json(await auth.listUsers(page(url),guard));
                    else if (c && method === 'GET')
                        res = json(present(await auth.getUser(c,guard)));
                    else if (c && method === 'PATCH')
                        res = json(await auth.updateUser(c, { data: input.data, status: input.status, email: input.email },guard));
                    else if (c && method === 'DELETE') {
                        await auth.deleteUser(c,guard);
                        res = empty();
                    }
                    else
                        fail('NOT_FOUND');
                }
                else if (b === 'tenants' && !d) {
                    if (!c && method === 'POST')
                        res = json(await auth.createTenant({ id: input.id, data: input.data },guard), 201);
                    else if (!c && method === 'GET')
                        res = json(await auth.listTenants(page(url),guard));
                    else if (c && method === 'GET')
                        res = json(present(await auth.getTenant(c,guard)));
                    else if (c && method === 'PATCH')
                        res = json(await auth.updateTenant(c, { data: input.data, status: input.status },guard));
                    else if (c && method === 'DELETE') {
                        await auth.deleteTenant(c,guard);
                        res = empty();
                    }
                    else
                        fail('NOT_FOUND');
                }
                else if ((b==='users'||b==='services')&&c&&d==='claims'&&seg.length<=5){
                    if(!e&&method==='GET')res=json(await auth.listTenantIds(c,page(url),guard));
                    else if(e&&method==='PUT')res=json(await auth.setClaims(c,e,input.claims,guard));
                    else if(e&&method==='GET')res=json(present(await auth.getClaims(c,e,guard)));
                    else if(e&&method==='DELETE'){await auth.revokeTenantAccess(c,e,guard);res=empty();}else fail('NOT_FOUND');
                }
                else if(b==='invitations'&&c&&method==='DELETE'){await auth.revokeInvitation(c,guard);res=empty();}
                else if(b==='services'&&c&&d==='api-keys'){
                    if(!e&&method==='POST')res=json(await auth.createApiKey({subjectId:c,tenantId:op.tenantId,name:input.name,claims:input.claims,expiresAt:input.expiresAt},undefined,guard),201);
                    else if(!e&&method==='GET')res=json(await auth.listApiKeys({subjectId:c,tenantId:op.tenantId,...page(url)},undefined,guard));
                    else if(e&&f==='rotate'&&method==='POST')res=json(await auth.rotateApiKey(e,undefined,guard),201);
                    else if(e&&!f&&method==='GET')res=json(present(await auth.getApiKey(e,undefined,guard)));
                    else if(e&&!f&&method==='PATCH')res=json(await auth.updateApiKey(e,{name:input.name,claims:input.claims},undefined,guard));
                    else if(e&&!f&&method==='DELETE'){await auth.revokeApiKey(e,undefined,guard);res=empty();}else fail('NOT_FOUND');
                }
                else if(b==='services'&&!d){
                    if(!c&&method==='POST')res=json(await auth.createServiceAccount({tenantId:op.tenantId,name:input.name,claims:input.claims,data:input.data},guard),201);
                    else if(!c&&method==='GET')res=json(await auth.listServiceAccounts(op.tenantId!,page(url),guard));
                    else if(c&&method==='GET')res=json(present(await auth.getServiceAccount(c,guard)));
                    else if(c&&method==='PATCH')res=json(await auth.updateServiceAccount(c,{name:input.name,status:input.status,data:input.data},guard));
                    else if(c&&method==='DELETE'){await auth.deleteServiceAccount(c,guard);res=empty();}else fail('NOT_FOUND');
                }
                else
                    fail('NOT_FOUND');
            }
            else
                fail('NOT_FOUND');
            return cors(res, origin);
        }
        catch (error) {
            const code = error instanceof AuthError ? error.code : 'UNAVAILABLE';
            try {
                options.onError?.(code);
            }
            catch {
            }
            const res = json({ error: code, ...(error instanceof SchemaValidationError?{issues:error.issues}:{}) }, status[code]);
            if (code === 'UNAUTHENTICATED')
                res.headers.set('www-authenticate', 'Bearer realm="defuss-auth"');
            if (code === 'RATE_LIMIT')
                res.headers.set('retry-after', '60');
            return cors(res, origin);
        }
    }
    return Object.freeze({ matches, fetch: handle });
}
export function authPlugin<S extends SchemaSet>(auth: Auth<S>, options: HandlerOptions = {}): ServePlugin {
    const h = createAuthHandler(auth, options);
    return Object.freeze({ name: 'defuss-auth', ...h, ...options.ownAuth ? { close: () => auth.close() } : {} });
}
