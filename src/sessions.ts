/** sessions operations: explicit dependencies, no global authority. */
import type { Principal } from './auth.js';
import { next,type OperationsContext } from './context.js';
import type { ListOptions } from './providers.js';
import { canonicalEmail,fail,id,identifier,opaque,opaqueId,password,tag,verifyTag } from './util.js';
export function createSessionsOperations(ctx: OperationsContext) {
    const { provider, tx, get, state, now, p, hasher, dummyHash, throttle, newSession, issue, sessionValid, checkedProof, requirePrincipal, authenticate, emit } = ctx;
    const api = {
        async login(input: {
            email: string;
            password: string;
            tenantId?: string;
            rateKey?: string;
        }) {
            const email = canonicalEmail(input.email), pw = password(input.password, 1), tenantId = identifier(input.tenantId ?? 'default');
            await throttle('public-global', 'all', p.globalRateAttempts);
            if (input.rateKey)
                await throttle('login-source', input.rateKey, p.rateAttempts * 5);
            const snapshot = await provider.read(async (r) => {
                const [u] = await r.list('users', {
                    where: { emailCanonical: email }, limit: 1
                });
                return { u, c: u ? await r.get('credentials', u.id) : undefined };
            });
            await throttle('login-account', email);
            const valid = await hasher.verify(pw, snapshot.c?.hash ?? dummyHash);
            if (!valid || !snapshot.u || !snapshot.c)
                fail('UNAUTHENTICATED');
            const upgraded = hasher.needsRehash?.(snapshot.c.hash) ? await hasher.hash(pw) : undefined;
            const result = await tx(async (w) => {
                const st = await state(w, snapshot.u!.id, tenantId), c = await w.get('credentials', st.u.id);
                if (c?.version !== snapshot.c!.version || st.u.kind !== 'user' || st.u.email !== email || st.u.epoch !== snapshot.u!.epoch)
                    fail('UNAUTHENTICATED');
                if (upgraded)
                    await w.put('credentials', { ...snapshot.c!, hash: upgraded });
                return newSession(w, st, now());
            });
            await emit({ type: 'session.login', at: now(), userId: snapshot.u.id, tenantId });
            return result;
        },
        authenticate,
        async requireAuth(input: string | Headers | Request, opts: {
            tenantId?: string;
            claims?: string[];
            anyClaims?: string[];
        } = {}) {
            const q = await authenticate(input, opts);
            if (opts.claims && !q.hasAllClaims(opts.claims) || opts.anyClaims && !q.hasAnyClaim(opts.anyClaims))
                fail('FORBIDDEN');
            return q;
        },
        async refresh(refreshToken: string) {
            let tokenId: string;
            try {
                tokenId = opaqueId('dfr_', refreshToken);
            }
            catch {
                fail('UNAUTHENTICATED');
            }
            const result = await tx(async (w) => {
                const time = now(), rf = await w.get('refresh', tokenId);
                if (!rf || rf.expiresAt <= time || !await verifyTag('refresh', refreshToken, rf.digest))
                    return null;
                const s = await w.get('sessions', rf.sid);
                if (!s)
                    return null;
                if (rf.used) {
                    if (s.revokedAt === null) {
                        s.revokedAt = time;
                        await w.put('sessions', s);
                    }
                    return null;
                }
                const st = await state(w, s.userId, s.tenantId);
                if (!sessionValid(s, st, time))
                    return null;
                rf.used = true;
                await w.put('refresh', rf);
                const fresh = opaque('dfr_');
                await w.insert('refresh', { id: fresh.keyId, sid: s.id, digest: await tag('refresh', fresh.secret), expiresAt: s.expiresAt, used: false });
                s.idleUntil = Math.min(s.expiresAt, time + p.idleTtlMs);
                await w.put('sessions', s);
                return { ...await issue(w, s, st, time), refreshToken: fresh.secret, sessionId: s.id, refreshExpiresAt: s.idleUntil };
            });
            if (!result)
                fail('UNAUTHENTICATED');
            return result;
        },
        async logout(principal: Principal) {
            requirePrincipal(principal);
            await tx(async (w) => {
                const { s } = await checkedProof(w, principal);
                s.revokedAt = now();
                await w.put('sessions', s);
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async logoutRefresh(token: string) {
            let k: string;
            try {
                k = opaqueId('dfr_', token);
            }
            catch {
                return;
            }
            await tx(async (w) => {
                const rf = await w.get('refresh', k);
                if (!rf || !await verifyTag('refresh', token, rf.digest))
                    return;
                const s = await w.get('sessions', rf.sid);
                if (s && s.revokedAt === null) {
                    s.revokedAt = now();
                    await w.put('sessions', s);
                }
            });
        },
        async logoutAll(principal: Principal, scope: 'tenant' | 'all' = 'tenant') {
            requirePrincipal(principal);
            await tx(async (w) => {
                const { st } = await checkedProof(w, principal, true);
                if (scope === 'all') {
                    st.u.sessionEpoch = next(st.u.sessionEpoch);
                    if (st.u.kind !== 'user')
                        fail('FORBIDDEN');
                    await w.putCompact('users', st.u);
                }
                else if (scope === 'tenant') {
                    st.m.sessionEpoch = next(st.m.sessionEpoch);
                    await w.put('grants', st.m);
                }
                else
                    fail('INVALID_INPUT');
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async revokeToken(token: string, principal?: Principal) {
            const q = await authenticate('Bearer ' + token);
            if (principal) {
                requirePrincipal(principal);
                if (principal.method !== 'jwt' || principal.subjectId !== q.subjectId || principal.tenantId !== q.tenantId)
                    fail('FORBIDDEN');
            }
            await tx(async (w) => {
                if (principal)
                    await checkedProof(w, principal); // A bounded retention horizon covers every token this authority can issue.
                await w.put('revocations', { id: q.tokenId!, expiresAt: now() + (86400 + 300 + 1) * 1000 });
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async listSessions(principal: Principal, page: ListOptions = {}) {
            requirePrincipal(principal);
            return provider.read(async (r) => {
                await checkedProof(r, principal);
                return (await r.list('sessions', {
                    where: { userId: principal.subjectId, tenantId: principal.tenantId }, limit: page.limit, after: page.after
                })).map(s => ({ id: s.id, createdAt: s.createdAt, expiresAt: s.expiresAt, idleUntil: s.idleUntil, revokedAt: s.revokedAt }));
            });
        },
        async revokeSession(principal: Principal, sid: string) {
            requirePrincipal(principal);
            await tx(async (w) => {
                await checkedProof(w, principal);
                const s = await w.get('sessions', identifier(sid));
                if (!s || s.userId !== principal.subjectId || s.tenantId !== principal.tenantId)
                    fail('NOT_FOUND');
                s.revokedAt = now();
                await w.put('sessions', s);
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async switchTenant(principal: Principal, tenantId: string) {
            requirePrincipal(principal);
            return tx(async (w) => {
                const { s } = await checkedProof(w, principal);
                const st = await state(w, principal.subjectId, identifier(tenantId));
                const tokens = await newSession(w, st, now(), s.proofAt);
                s.revokedAt = now();
                await w.put('sessions', s);
                return tokens;
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async stepUp(principal: Principal, currentPassword: string) {
            requirePrincipal(principal);
            await throttle('step-up', principal.subjectId);
            const c = await provider.read(async (r) => { await checkedProof(r, principal); return get(r, 'credentials', principal.subjectId); });
            if (!await hasher.verify(password(currentPassword, 1), c.hash))
                fail('UNAUTHENTICATED');
            return tx(async (w) => { const { s, st } = await checkedProof(w, principal); if ((await get(w, 'credentials', st.u.id)).version !== c.version)
                fail('CONFLICT'); s.revokedAt = now(); await w.put('sessions', s); return newSession(w, st, now()); }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async changePassword(principal: Principal, current: string, replacement: string) {
            requirePrincipal(principal);
            const pw = password(current, 1), nextPw = password(replacement, p.passwordMinLength);
            await throttle('password-change', principal.subjectId);
            const c = await provider.read(async (r) => {
                await checkedProof(r, principal);
                return get(r, 'credentials', principal.subjectId);
            });
            if (!await hasher.verify(pw, c.hash))
                fail('UNAUTHENTICATED');
            const hash = await hasher.hash(nextPw);
            await tx(async (w) => {
                const { st } = await checkedProof(w, principal);
                if ((await get(w, 'credentials', st.u.id)).version !== c.version)
                    fail('CONFLICT');
                await w.put('credentials', { id: st.u.id, hash, version: id() });
                st.u.epoch = next(st.u.epoch);
                if (st.u.kind !== 'user')
                    fail('FORBIDDEN');
                await w.putCompact('users', st.u);
            }, undefined, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async setPassword(userId: string, replacement: string) {
            const hash = await hasher.hash(password(replacement, p.passwordMinLength));
            await tx(async (w) => {
                const u = await get(w, 'users', identifier(userId));
                if (u.status === 'deleted')
                    fail('NOT_FOUND');
                await w.put('credentials', { id: u.id, hash, version: id() });
                u.epoch = next(u.epoch);
                await w.put('users', u);
            });
        }
    };
    return api;
}
