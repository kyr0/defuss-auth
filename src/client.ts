/** Lightweight Fetch client. Imports no authority, database or platform adapter at runtime. */
import type { Principal,SessionTokens } from './auth.js';
import type { ApiKey,ServiceAccount,Tenant,User } from './records.js';
import type { SchemaData,SchemaSet } from './schema.js';
export class AuthClientError extends Error {
    constructor(readonly status: number, readonly code: string, readonly issues?:readonly import('./schema.js').SchemaIssue[]) {
        super(code);
        this.name = 'AuthClientError';
    }
}
export type ClientPrincipal = Pick<Principal, 'subjectId' | 'subjectKind' | 'tenantId' | 'claims' | 'method' | 'sessionId'>;
export interface ClientOptions<S extends SchemaSet=SchemaSet> {
    /** Type inference only; the authority validates all data. */
    schemas?:S;
    baseUrl: string;
    mode?: 'cookie' | 'token';
    fetch?: typeof fetch;
    onAuthChange?: (state: ClientState) => void;
}
export interface ClientState {
    authenticated: boolean;
    method: 'jwt' | 'apiKey' | null;
    expiresAt?: number;
}
export function createAuthClient<const S extends SchemaSet=SchemaSet>(options: ClientOptions<S>) {
    const base = new URL(options.baseUrl);
    if (base.username || base.password || base.search || base.hash || !['https:', 'http:'].includes(base.protocol) || base.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(base.hostname))
        throw new Error('Invalid auth base URL');
    base.pathname = base.pathname.replace(/\/$/, '');
    const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis), mode = options.mode ?? 'cookie';
    if (!['cookie', 'token'].includes(mode))
        throw new Error('Invalid mode');
    let access: string | undefined, refreshToken: string | undefined, key: string | undefined, expiresAt: number | undefined;
    let queue = Promise.resolve(), refreshFlight: Promise<boolean> | undefined;
    let identityEpoch = 0, sessionId: string | undefined;
    const listeners = new Set<(s: ClientState) => void>();
    if (options.onAuthChange)
        listeners.add(options.onAuthChange);
    const state = (): ClientState => Object.freeze({ authenticated: !!(key || access), method: key ? 'apiKey' : access ? 'jwt' : null, expiresAt });
    function notify() {
        for (const f of listeners)
            try {
                f(state());
            }
            catch {
            }
    }
    function clear() {
        identityEpoch++;
        sessionId = undefined;
        access = refreshToken = key = undefined;
        expiresAt = undefined;
        notify();
    }
    function accept(t: SessionTokens, rotated = false) {
        if (typeof t.accessToken !== 'string' || typeof t.sessionId !== 'string' || typeof t.expiresAt !== 'number' || mode === 'token' && typeof t.refreshToken !== 'string')
            throw new Error('Invalid token response');
        if (rotated && sessionId && sessionId !== t.sessionId) {
            clear();
            throw new AuthClientError(401, 'SESSION_CHANGED');
        }
        if (!rotated)
            identityEpoch++;
        sessionId = t.sessionId;
        access = t.accessToken;
        expiresAt = t.expiresAt;
        key = undefined;
        refreshToken = mode === 'token' ? t.refreshToken : undefined;
        notify();
    }
    function serialize<T>(fn: () => Promise<T>): Promise<T> {
        const run = queue.then(async () => {
            const locks = typeof navigator === 'undefined' ? undefined : navigator.locks;
            return mode === 'cookie' && locks ? locks.request('defuss-auth:' + base.href, fn) : fn();
        });
        queue = run.then(() => {
        }, () => {
        });
        return run;
    }
    async function request<T>(path: string, method = 'GET', data?: unknown, attach = true): Promise<T> {
        if (!path.startsWith('/') || path.includes('..') || path.startsWith('//'))
            throw new Error('Invalid endpoint');
        const url = new URL(base.href + path);
        if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname + '/'))
            throw new Error('Invalid endpoint');
        const headers = new Headers({ 'accept': 'application/json' });
        if (method !== 'GET' && method !== 'HEAD')
            headers.set('x-defuss-csrf', '1');
        if (data !== undefined)
            headers.set('content-type', 'application/json');
        if (attach && (key || access))
            headers.set('authorization', key ? 'ApiKey ' + key : 'Bearer ' + access);
        const res = await fetcher(url, { method, headers, body: data === undefined ? undefined : JSON.stringify(data), credentials: mode === 'cookie' ? 'include' : 'omit', redirect: 'error', cache: 'no-store' });
        if (!res.ok) {
            let code='HTTP_ERROR',issues:readonly import('./schema.js').SchemaIssue[]|undefined;
            try{const e=await res.json();code=e.error??code;issues=Array.isArray(e.issues)?e.issues:undefined;}
            catch {
            }
            throw new AuthClientError(res.status, code,issues);
        }
        return res.status === 204 ? undefined as T : await res.json() as T;
    }
    function refresh(expectedEpoch = identityEpoch): Promise<boolean> {
        if (key || expectedEpoch !== identityEpoch)
            return Promise.resolve(false);
        if (refreshFlight)
            return refreshFlight;
        refreshFlight = serialize(async () => {
            if (expectedEpoch !== identityEpoch || key || mode === 'token' && !refreshToken)
                return false;
            try {
                accept(await request<SessionTokens>('/refresh', 'POST', mode === 'token' ? { refreshToken } : {}, false), true);
                return true;
            }
            catch (e) {
                clear();
                if (e instanceof AuthClientError && e.status === 401)
                    return false;
                throw e;
            }
        });
        void refreshFlight.then(() => {
            refreshFlight = undefined;
        }, () => {
            refreshFlight = undefined;
        });
        return refreshFlight;
    }
    function qs(page?: {
        limit?: number;
        after?: string;
    }) {
        const q = new URLSearchParams();
        if (page?.limit !== undefined)
            q.set('limit', String(page.limit));
        if (page?.after !== undefined)
            q.set('after', page.after);
        return q.size ? '?' + q : '';
    }
    function pathId(s: string) {
        if (!/^[A-Za-z0-9_-]+$/.test(s))
            throw new Error('Invalid ID');
        return s;
    }
    const api = {
        state, subscribe(listener: (s: ClientState) => void) {
            listeners.add(listener);
            listener(state());
            return () => listeners.delete(listener);
        }, refresh: () => refresh(),
        login: (input: {
            email: string;
            password: string;
            tenantId?: string;
        }) => serialize(async () => {
            const t = await request<SessionTokens>('/login', 'POST', input, false);
            accept(t);
            return state();
        }),
        requestPasswordlessLogin:(input:{email:string;tenantId?:string})=>request<void>('/login/email/request','POST',input,false),
        confirmPasswordlessLogin:(token:string)=>serialize(async()=>{accept(await request<SessionTokens>('/login/email/confirm','POST',{token},false));return state();}),
        requestRegistration:(input:{email:string;data?:SchemaData<S,'user'>})=>request<void>('/register/request','POST',input,false),
        confirmRegistration:(input:{token:string;password?:string})=>request<void>('/register/confirm','POST',input,false),
        acceptInvitation:(input:{token:string;password?:string;data?:SchemaData<S,'user'>})=>request<void>('/invitation/accept','POST',input,false),
        stepUp:(password:string)=>serialize(async()=>{accept(await request<SessionTokens>('/password/step-up','POST',{password}));return state();}),
        setApiKey: (value: string) => serialize(async () => {
            if (!/^dfa_[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(value))
                throw new Error('Invalid API key');
            clear();
            key = value;
            notify();
        }),
        setAccessToken: (value: string) => serialize(async () => {
            if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value))
                throw new Error('Invalid token');
            clear();
            access = value;
            notify();
        }),
        logout: () => serialize(async () => {
            try {
                if (!key)
                    await request('/logout', 'POST', mode === 'token' ? { refreshToken } : {});
            }
            finally {
                clear();
            }
        }),
        logoutAll: (scope: 'tenant' | 'all' = 'tenant') => serialize(async () => {
            await request('/logout-all', 'POST', { scope });
            clear();
        }),
        me: () => request<ClientPrincipal>('/me'),
        listTenants: (page?: {
            limit?: number;
            after?: string;
        }) => request<string[]>('/tenants' + qs(page)),
        switchTenant: (tenantId: string) => serialize(async () => {
            accept(await request<SessionTokens>('/tenant/switch', 'POST', { tenantId }));
            return state();
        }),
        revokeToken: (token: string) => request<void>('/token/revoke', 'POST', { token }),
        listSessions: (page?: {
            limit?: number;
            after?: string;
        }) => request<{
            id: string;
            createdAt: number;
            expiresAt: number;
            idleUntil: number;
            revokedAt: number | null;
        }[]>('/sessions' + qs(page)),
        revokeSession: (sid: string) => request<void>('/sessions/' + pathId(sid), 'DELETE'),
        changePassword: (currentPassword: string, newPassword: string) => serialize(async () => {
            await request('/password/change', 'POST', { currentPassword, newPassword });
            clear();
        }),
        requestPasswordReset: (input: {
            email: string;
        }) => request<void>('/password/reset/request', 'POST', input, false),
        resetPassword: (input: {
            token: string;
            newPassword: string;
        }) => request<void>('/password/reset/confirm', 'POST', input, false),
        requestEmailVerification: (input: {
            email: string;
        }) => request<void>('/email/verify/request', 'POST', input, false),
        verifyEmail: (token: string) => request<void>('/email/verify/confirm', 'POST', { token }, false),
        createApiKey: (input: {
            name: string;
            claims?: string[];
            expiresAt?: number;
        }) => request<{
            apiKey: string;
            record: ApiKey;
        }>('/api-keys', 'POST', input),
        listApiKeys: (page?: {
            limit?: number;
            after?: string;
        }) => request<ApiKey[]>('/api-keys' + qs(page)),
        getApiKey: (id: string) => request<ApiKey>('/api-keys/' + pathId(id)),
        updateApiKey: (id: string, patch: {
            name?: string;
            claims?: string[];
        }) => request<ApiKey>('/api-keys/' + pathId(id), 'PATCH', patch),
        revokeApiKey: (id: string) => request<void>('/api-keys/' + pathId(id), 'DELETE'),
        rotateApiKey: (id: string) => request<{
            apiKey: string;
            record: ApiKey;
        }>('/api-keys/' + pathId(id) + '/rotate', 'POST', {}),
        admin: {
            createUser: (input: {
                email: string;
                password?: string;
                data?: SchemaData<S,'user'>;
                joinDefault?: boolean;
            }) => request<User<SchemaData<S,'user'>>>('/admin/users', 'POST', input), listUsers: (p?: {
                limit?: number;
                after?: string;
            }) => request<User<SchemaData<S,'user'>>[]>('/admin/users' + qs(p)), getUser: (id: string) => request<User<SchemaData<S,'user'>>>('/admin/users/' + pathId(id)), updateUser: (id: string, patch: {
                email?: string;
                status?: 'active' | 'disabled';
                data?: SchemaData<S,'user'>;
            }) => request<User<SchemaData<S,'user'>>>('/admin/users/' + pathId(id), 'PATCH', patch), deleteUser: (id: string) => request<void>('/admin/users/' + pathId(id), 'DELETE'), createTenant: (input: {
                id?: string;
                data?: SchemaData<S,'tenant'>;
            }) => request<Tenant<SchemaData<S,'tenant'>>>('/admin/tenants', 'POST', input), listTenants: (p?: {
                limit?: number;
                after?: string;
            }) => request<Tenant<SchemaData<S,'tenant'>>[]>('/admin/tenants' + qs(p)), getTenant: (id: string) => request<Tenant<SchemaData<S,'tenant'>>>('/admin/tenants/' + pathId(id)), updateTenant: (id: string, patch: {
                status?: 'active' | 'disabled';
                data?: SchemaData<S,'tenant'>;
            }) => request<Tenant<SchemaData<S,'tenant'>>>('/admin/tenants/' + pathId(id), 'PATCH', patch), deleteTenant: (id: string) => request<void>('/admin/tenants/' + pathId(id), 'DELETE'),
            listTenantIds: (uid:string,p?:{limit?:number;after?:string})=>request<string[]>('/admin/users/'+pathId(uid)+'/claims'+qs(p)),
            getClaims: (uid:string,tid:string)=>request<string[]>('/admin/users/'+pathId(uid)+'/claims/'+pathId(tid)),
            setClaims: (uid:string,tid:string,claims:string[])=>request<string[]>('/admin/users/'+pathId(uid)+'/claims/'+pathId(tid),'PUT',{claims}),
            revokeTenantAccess: (uid:string,tid:string)=>request<void>('/admin/users/'+pathId(uid)+'/claims/'+pathId(tid),'DELETE'),
            inviteToTenant: (input:{email:string;tenantId:string;claims?:string[]})=>request<{id:string;tenantId:string;expiresAt:number}>('/admin/invitations','POST',input),
            revokeInvitation:(id:string)=>request<void>('/admin/invitations/'+pathId(id),'DELETE'),
            createServiceApiKey:(id:string,input:{name:string;claims?:string[];expiresAt?:number})=>request<{apiKey:string;record:ApiKey}>('/admin/services/'+pathId(id)+'/api-keys','POST',input),
            listServiceApiKeys:(id:string,p?:{limit?:number;after?:string})=>request<ApiKey[]>('/admin/services/'+pathId(id)+'/api-keys'+qs(p)),
            getServiceApiKey:(id:string,k:string)=>request<ApiKey>('/admin/services/'+pathId(id)+'/api-keys/'+pathId(k)),
            updateServiceApiKey:(id:string,k:string,patch:{name?:string;claims?:string[]})=>request<ApiKey>('/admin/services/'+pathId(id)+'/api-keys/'+pathId(k),'PATCH',patch),
            rotateServiceApiKey:(id:string,k:string)=>request<{apiKey:string;record:ApiKey}>('/admin/services/'+pathId(id)+'/api-keys/'+pathId(k)+'/rotate','POST',{}),
            revokeServiceApiKey:(id:string,k:string)=>request<void>('/admin/services/'+pathId(id)+'/api-keys/'+pathId(k),'DELETE'),
            createServiceAccount: (input:{tenantId?:string;name:string;claims?:string[];data?:SchemaData<S,'service'>})=>request<ServiceAccount<SchemaData<S,'service'>>>('/admin/services','POST',input),
            getServiceAccount: (id:string)=>request<ServiceAccount<SchemaData<S,'service'>>>('/admin/services/'+pathId(id)),
            listServiceAccounts: (tenantId='default',page?:{limit?:number;after?:string})=>request<ServiceAccount<SchemaData<S,'service'>>[]>('/admin/services'+(qs(page)||'?')+(qs(page)?'&':'')+'tenantId='+encodeURIComponent(tenantId)),
            updateServiceAccount: (id:string,patch:{name?:string;status?:'active'|'disabled';data?:SchemaData<S,'service'>})=>request<ServiceAccount<SchemaData<S,'service'>>>('/admin/services/'+pathId(id),'PATCH',patch),
            deleteServiceAccount: (id:string)=>request<void>('/admin/services/'+pathId(id),'DELETE'),
            setServiceClaims:(id:string,tenantId:string,claims:string[])=>request<string[]>('/admin/services/'+pathId(id)+'/claims/'+pathId(tenantId),'PUT',{claims}),
            getServiceClaims:(id:string,tenantId:string)=>request<string[]>('/admin/services/'+pathId(id)+'/claims/'+pathId(tenantId)),
            listServiceTenantIds:(id:string,p?:{limit?:number;after?:string})=>request<string[]>('/admin/services/'+pathId(id)+'/claims'+qs(p)),
            revokeServiceTenantAccess:(id:string,tenantId:string)=>request<void>('/admin/services/'+pathId(id)+'/claims/'+pathId(tenantId),'DELETE')
        },
        /** Only GET/HEAD may be replayed after a successful refresh. Credentials never cross origins. */
        async fetch(input: string | URL, init: RequestInit = {}) {
            const url = new URL(input, base.origin);
            if (url.origin !== base.origin || url.username || url.password)
                throw new Error('Credential origin mismatch');
            const method = (init.method ?? 'GET').toUpperCase();
            const send = (credential: string | undefined) => {
                const headers = new Headers(init.headers);
                headers.delete('authorization');
                if(credential) headers.set('authorization',credential);
                return fetcher(url, { ...init, headers, redirect: 'error', credentials: 'omit' });
            };
            const before = access, epoch = identityEpoch;
            const first = await send(key ? 'ApiKey '+key : before ? 'Bearer '+before : undefined);
            if (first.status !== 401 || identityEpoch !== epoch || key || !['GET', 'HEAD'].includes(method) || !before)
                return first;
            if ((access !== before && access || await refresh(epoch)) && identityEpoch === epoch) {
                const rotated=access;
                // Cancellation may call user/stream code and allow a different login to finish.
                // Never send an old request with a new identity's credential.
                if(identityEpoch!==epoch||key||!rotated)return first;
                // Do not await cancellation before replay; release body in the background.
                // Calling send synchronously captures the immutable rotated credential.
                const replay=send('Bearer '+rotated);
                void first.body?.cancel().catch(()=>{});
                return replay;
            }
            return first;
        }
    };
    return Object.freeze({ ...api, admin: Object.freeze(api.admin) });
}
export type AuthClient = ReturnType<typeof createAuthClient>;
