/** challenges operations: explicit dependencies, no global authority. */
import type { AdminGuard } from './auth.js';
import { assertActive,next,type OperationsContext } from './context.js';
import type { AuthReadStore,AuthWriteStore } from './persistence.js';
import { grantId,publicUser,type Challenge,type UserRow } from './records.js';
import { canonicalEmail,claimSet,fail,freeze,id,identifier,opaque,opaqueId,password,tag,verifyTag,type Data } from './util.js';
export function createChallengesOperations(ctx: OperationsContext) {
    const { provider, tx, get, state, now, p, hasher, data, defaultEnabled, options, throttle, newSession, emit } = ctx;
    async function checkChallenge(r: AuthReadStore, kind: Challenge['kind'], token: string, challengeId: string) {
        const row = await r.get('challenges', challengeId);
        if (!row || row.kind !== kind || row.used || row.expiresAt <= now() || !await verifyTag('challenge:' + kind, token, row.digest))
            fail('UNAUTHENTICATED');
        const u = await r.get('users', row.userId);
        assertActive(u);
        if (u!.epoch !== row.epoch || u!.email !== row.email || (await r.get('credentials', u!.id))?.version !== (row.credentialVersion ?? undefined))
            fail('UNAUTHENTICATED');
        return { row, u: u! };
    }
    async function readChallenge(kind: Challenge['kind'], token: string) {
        let cid: string;
        try {
            cid = opaqueId('dfc_', token);
        }
        catch {
            fail('UNAUTHENTICATED');
        }
        return (await provider.read(r => checkChallenge(r, kind, token, cid))).row;
    }
    async function requestChallenge(kind: 'reset' | 'verify' | 'login', emailInput: string, rateKey?: string, tenantId?: string) {
        const email = canonicalEmail(emailInput);
        await throttle('public-global', 'all', p.globalRateAttempts);
        if (rateKey)
            await throttle('challenge-source', rateKey, p.rateAttempts * 5);
        await throttle('challenge:' + kind, email);
        if (!options.delivery)
            return;
        const secret = opaque('dfc_'), digest = await tag('challenge:' + kind, secret.secret);
        const row = await tx(async (w) => {
            const [u] = await w.list('users', {
                where: { emailCanonical: email }, limit: 1
            });
            if (!u || u.status !== 'active' || kind === 'verify' && u.emailVerified)
                return undefined;
            const c = await w.get('credentials', u.id);
            const t = tenantId ? await w.get('tenants', tenantId) : undefined, g = tenantId ? await w.get('grants', grantId(u.id, tenantId)) : undefined;
            if (tenantId && (!t || t.status !== 'active' || !g))
                return undefined;
            const r: Challenge = { id: secret.keyId, kind, ...(tenantId ? { tenantId, tenantEpoch: t!.epoch, grantIncarnation: g!.incarnation } : {}), userId: u.id, email: u.email, epoch: u.epoch, credentialVersion: c?.version ?? null, digest, expiresAt: now() + p.challengeTtlMs, used: false };
            await w.insert('challenges', r);
            return r;
        });
        if (row)
            await deliver(row, secret.secret);
    }
    async function deliver(row: Challenge, token: string) { try {
        await options.delivery?.({ kind: row.kind, email: row.email, token, expiresAt: row.expiresAt, tenantId: row.tenantId });
    }
    catch {
        await emit({ type: 'challenge.delivery_failed', at: now() });
    } }
    async function unboundChallenge(r: AuthReadStore, kind: 'invite' | 'register', token: string) { const cid = opaqueId('dfc_', token), row = await r.get('challenges', cid); if (!row || row.kind !== kind || row.used || row.expiresAt <= now() || !await verifyTag('challenge:' + kind, token, row.digest))
        fail('UNAUTHENTICATED'); return row; }
    async function createVerifiedUser(w: AuthWriteStore, email: string, d: Data, hash?: string) { const u: UserRow = { kind: 'user', id: id(), email, emailCanonical: email, emailVerified: true, status: 'active', createdAt: now(), updatedAt: now(), data: d, epoch: 1, sessionEpoch: 1 }; await w.insert('users', u); if (hash)
        await w.insert('credentials', { id: u.id, hash, version: id() }); return u; }
    const api = {
        async requestPasswordReset(email: string, rateKey?: string) {
            return requestChallenge('reset', email, rateKey);
        },
        async requestEmailVerification(email: string, rateKey?: string) {
            return requestChallenge('verify', email, rateKey);
        },
        async resetPassword(token: string, replacement: string) {
            const pw = password(replacement, p.passwordMinLength);
            const c = await readChallenge('reset', token);
            const hash = await hasher.hash(pw);
            await tx(async (w) => {
                const { row, u } = await checkChallenge(w, 'reset', token, c.id);
                row.used = true;
                await w.put('challenges', row);
                await w.put('credentials', { id: u.id, hash, version: id() });
                u.epoch = next(u.epoch);
                await w.put('users', u);
            });
        },
        async verifyEmail(token: string) {
            const c = await readChallenge('verify', token);
            await tx(async (w) => {
                const { row, u } = await checkChallenge(w, 'verify', token, c.id);
                row.used = true;
                await w.put('challenges', row);
                u.emailVerified = true;
                u.updatedAt = now();
                await w.put('users', u);
            });
        },
        async requestPasswordlessLogin(input: {
            email: string;
            tenantId?: string;
            rateKey?: string;
        }) {
            if (!options.passwordless)
                fail('FORBIDDEN');
            return requestChallenge('login', input.email, input.rateKey, identifier(input.tenantId ?? 'default'));
        },
        async confirmPasswordlessLogin(token: string) {
            if (!options.passwordless)
                fail('FORBIDDEN');
            const c = await readChallenge('login', token);
            return tx(async (w) => { const { row, u } = await checkChallenge(w, 'login', token, c.id); const tid = row.tenantId!; const t = await get(w, 'tenants', tid); if (t.epoch !== row.tenantEpoch)
                fail('UNAUTHENTICATED'); u.emailVerified = true; await w.put('users', u); const st = await state(w, u.id, tid); if (st.m.incarnation !== row.grantIncarnation)
                fail('UNAUTHENTICATED'); row.used = true; await w.put('challenges', row); return newSession(w, st, now(), -1); });
        },
        async inviteToTenant(input: {
            email: string;
            tenantId: string;
            claims?: string[];
        }, guard?: AdminGuard) {
            if (!options.delivery)
                fail('UNAVAILABLE', 'Delivery not configured');
            const email = canonicalEmail(input.email), tenantId = identifier(input.tenantId), claims = claimSet(input.claims ?? []);
            const secret = opaque('dfc_'), digest = await tag('challenge:invite', secret.secret);
            const row = await tx(async (w) => { const t = await get(w, 'tenants', tenantId); assertActive(t); const row: Challenge = { id: secret.keyId, kind: 'invite', userId: '', email, epoch: 0, credentialVersion: null, digest, expiresAt: now() + p.challengeTtlMs, used: false, tenantId, tenantEpoch: t.epoch, claims }; await w.insert('challenges', row); return row; }, guard);
            await deliver(row, secret.secret);
            return { id: row.id, tenantId: row.tenantId!, expiresAt: row.expiresAt };
        },
        async revokeInvitation(invitationId: string, guard?: AdminGuard) { await tx(async (w) => { const row = await get(w, 'challenges', identifier(invitationId)); if (row.kind !== 'invite')
            fail('NOT_FOUND'); row.used = true; await w.put('challenges', row); }, guard); },
        async acceptInvitation(input: {
            token: string;
            password?: string;
            data?: Data;
        }) {
            const c = await provider.read(r => unboundChallenge(r, 'invite', input.token));
            const hash = input.password === undefined ? undefined : await hasher.hash(password(input.password, p.passwordMinLength));
            return tx(async (w) => {
                const row = await unboundChallenge(w, 'invite', input.token);
                const tid = row.tenantId!, t = await get(w, 'tenants', tid);
                assertActive(t);
                if (t.epoch !== row.tenantEpoch || row.id !== c.id)
                    fail('UNAUTHENTICATED');
                let [u] = await w.list('users', { where: { emailCanonical: row.email }, limit: 1 });
                if (!u) {
                    if (!hash && !options.passwordless)
                        fail('INVALID_INPUT', 'Password required');
                    u = await createVerifiedUser(w, row.email, data('user', input.data ?? {}), hash);
                }
                else {
                    assertActive(u);
                    if (input.password !== undefined || input.data !== undefined)
                        fail('CONFLICT', 'Existing account: accept without profile or password');
                    u.emailVerified = true;
                    await w.put('users', u);
                }
                const k = grantId(u.id, tid);
                if (await w.get('grants', k))
                    fail('CONFLICT', 'Tenant access already exists');
                await w.insert('grants', { id: k, userId: u.id, tenantId: tid, claims: row.claims ?? [], revision: 1, incarnation: id(), sessionEpoch: 1 });
                row.used = true;
                await w.put('challenges', row);
                return { userId: u.id, tenantId: tid };
            });
        },
        async requestRegistration(input: {
            email: string;
            data?: Data;
            rateKey?: string;
        }) {
            if (!options.registration || !defaultEnabled || !options.delivery)
                fail('FORBIDDEN');
            const email = canonicalEmail(input.email), d = data('user', input.data ?? {}), tenantId = 'default';
            await throttle('public-global', 'all', p.globalRateAttempts);
            if (input.rateKey)
                await throttle('register-source', input.rateKey, p.rateAttempts * 5);
            await throttle('register-email', email);
            if (!await options.registration(freeze({ email, tenantId, data: d })))
                return;
            const secret = opaque('dfc_'), digest = await tag('challenge:register', secret.secret);
            const row = await tx(async (w) => { if ((await w.list('users', { where: { emailCanonical: email }, limit: 1 })).length)
                return; const t = await get(w, 'tenants', tenantId); assertActive(t); const row: Challenge = { id: secret.keyId, kind: 'register', email, userId: '', epoch: 0, credentialVersion: null, digest, expiresAt: now() + p.challengeTtlMs, used: false, tenantId, tenantEpoch: t.epoch, registrationData: d }; await w.insert('challenges', row); return row; });
            if (row)
                await deliver(row, secret.secret);
        },
        async confirmRegistration(input: {
            token: string;
            password?: string;
        }) {
            if (!options.registration)
                fail('FORBIDDEN');
            const initial = await provider.read(r => unboundChallenge(r, 'register', input.token));
            const d = data('user', initial.registrationData ?? {});
            if (!await options.registration(freeze({ email: initial.email, tenantId: 'default', data: d })))
                fail('FORBIDDEN');
            const hash = input.password === undefined ? undefined : await hasher.hash(password(input.password, p.passwordMinLength));
            if (!hash && !options.passwordless)
                fail('INVALID_INPUT', 'Password required');
            return tx(async (w) => { const row = await unboundChallenge(w, 'register', input.token); const t = await get(w, 'tenants', 'default'); assertActive(t); if (t.epoch !== row.tenantEpoch || row.id !== initial.id)
                fail('UNAUTHENTICATED'); if ((await w.list('users', { where: { emailCanonical: row.email }, limit: 1 })).length)
                fail('CONFLICT'); const u = await createVerifiedUser(w, row.email, d, hash); await w.insert('grants', { id: grantId(u.id, 'default'), userId: u.id, tenantId: 'default', claims: [], revision: 1, incarnation: id(), sessionEpoch: 1 }); row.used = true; await w.put('challenges', row); return publicUser(u); });
        }
    };
    return api;
}
