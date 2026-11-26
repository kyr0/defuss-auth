/** identity operations: explicit dependencies, no global authority. */
import type { AdminGuard } from './auth.js';
import { assertActive,next,sameClaims,type OperationsContext } from './context.js';
import type { ListOptions } from './providers.js';
import { grantId,publicService,publicTenant,publicUser,type ServiceRow,type TenantRow,type UserRow } from './records.js';
import { AuthError,canonicalEmail,claimSet,fail,id,identifier,password,string,type Data } from './util.js';
export function createIdentityOperations(ctx: OperationsContext) {
    const { provider, tx, read, get, state, data, hasher, now, p, defaultEnabled, autoJoin, emit } = ctx;
    const api = {
        async createServiceAccount(input: {
            tenantId?: string;
            name: string;
            claims?: string[];
            data?: Data;
        }, guard?: AdminGuard) {
            const tenantId = identifier(input.tenantId ?? 'default'), claims = claimSet(input.claims ?? []);
            const row: ServiceRow = { kind: 'service', id: id(), tenantId, name: string(input.name, 128), status: 'active', createdAt: now(), updatedAt: now(), epoch: 1, sessionEpoch: 1, data: data('service', input.data ?? {}) };
            await tx(async (w) => { assertActive(await w.get('tenants', tenantId)); await w.insert('services', row); await w.insert('grants', { id: grantId(row.id, tenantId), userId: row.id, tenantId, claims, revision: 1, incarnation: id(), sessionEpoch: 1 }); }, guard);
            return publicService(row);
        },
        async getServiceAccount(subjectId: string, guard?: AdminGuard) { const row = await read(r => r.get('services', identifier(subjectId)), guard); return row && row.status !== 'deleted' ? publicService(row) : undefined; },
        async listServiceAccounts(tenantId: string, page: ListOptions = {}, guard?: AdminGuard) { return (await read(r => r.list('services', { where: { tenantId: identifier(tenantId) }, limit: page.limit, after: page.after }), guard)).map(publicService); },
        async updateServiceAccount(subjectId: string, patch: {
            name?: string;
            status?: 'active' | 'disabled';
            data?: Data;
        }, guard?: AdminGuard) { return tx(async (w) => { const row = await get(w, 'services', identifier(subjectId)); if (row.status === 'deleted')
            fail('NOT_FOUND'); if (patch.name !== undefined)
            row.name = string(patch.name, 128); if (patch.data !== undefined)
            row.data = data('service', patch.data); if (patch.status !== undefined) {
            if (!['active', 'disabled'].includes(patch.status))
                fail('INVALID_INPUT');
            if (row.status !== patch.status) {
                row.status = patch.status;
                row.epoch = next(row.epoch);
            }
        } row.updatedAt = now(); await w.put('services', row); return publicService(row); }, guard); },
        async deleteServiceAccount(subjectId: string, guard?: AdminGuard) { await tx(async (w) => { const row = await get(w, 'services', identifier(subjectId)); row.status = 'deleted'; row.epoch = next(row.epoch); row.updatedAt = now(); await w.put('services', row); await w.delete('grants', grantId(row.id, row.tenantId)); }, guard); },
        async createUser(input: {
            email: string;
            password?: string;
            data?: Data;
            joinDefault?: boolean;
        }, guard?: AdminGuard) {
            const email = canonicalEmail(input.email), d = data('user', input.data ?? {}), hash = input.password === undefined ? undefined : await hasher.hash(password(input.password, p.passwordMinLength));
            const u: UserRow = { kind: 'user', id: id(), email, emailCanonical: email, emailVerified: false, status: 'active', createdAt: now(), updatedAt: now(), data: d, epoch: 1, sessionEpoch: 1 };
            const join = input.joinDefault ?? autoJoin;
            await tx(async (w) => {
                if ((await w.list('users', {
                    where: { emailCanonical: email }, limit: 1
                })).length)
                    fail('CONFLICT', 'Email exists');
                await w.insert('users', u);
                if (hash)
                    await w.insert('credentials', { id: u.id, hash, version: id() });
                if (defaultEnabled && join) {
                    assertActive(await w.get('tenants', 'default'));
                    await w.insert('grants', { id: grantId(u.id, 'default'), userId: u.id, tenantId: 'default', claims: [], revision: 1, incarnation: id(), sessionEpoch: 1 });
                }
            }, guard);
            await emit({ type: 'user.created', at: now(), userId: u.id });
            return publicUser(u);
        },
        async getUser(userId: string, guard?: AdminGuard) {
            const u = await read(r => r.get('users', identifier(userId)), guard);
            return u && u.status !== 'deleted' ? publicUser(u) : undefined;
        },
        async getUserByEmail(email: string) {
            const [u] = await provider.read(r => r.list('users', {
                where: { emailCanonical: canonicalEmail(email) }, limit: 1
            }));
            return u && u.status !== 'deleted' ? publicUser(u) : undefined;
        },
        async userExists(userId: string) {
            return !!await api.getUser(userId);
        },
        async listUsers(page: ListOptions = {}, guard?: AdminGuard) {
            return (await read(r => r.list('users', { limit: page.limit, after: page.after }), guard)).map(publicUser);
        },
        async updateUser(userId: string, patch: {
            data?: Data;
            status?: 'active' | 'disabled';
            email?: string;
        }, guard?: AdminGuard) {
            return tx(async (w) => {
                const u = await get(w, 'users', identifier(userId));
                if (u.status === 'deleted')
                    fail('NOT_FOUND');
                if (patch.data !== undefined)
                    u.data = data('user', patch.data);
                if (patch.status !== undefined) {
                    if (!['active', 'disabled'].includes(patch.status))
                        fail('INVALID_INPUT');
                    if (u.status !== patch.status) {
                        u.status = patch.status;
                        u.epoch = next(u.epoch);
                    }
                }
                if (patch.email !== undefined) {
                    const email = canonicalEmail(patch.email);
                    if (email !== u.email) {
                        if ((await w.list('users', {
                            where: { emailCanonical: email }, limit: 1
                        })).length)
                            fail('CONFLICT');
                        u.email = u.emailCanonical = email;
                        u.emailVerified = false;
                        u.epoch = next(u.epoch);
                    }
                }
                u.updatedAt = now();
                await w.put('users', u);
                return publicUser(u);
            }, guard);
        },
        async deleteUser(userId: string, guard?: AdminGuard) {
            await tx(async (w) => {
                const u = await get(w, 'users', identifier(userId));
                u.status = 'deleted';
                u.epoch = next(u.epoch);
                u.updatedAt = now();
                await w.put('users', u);
                await w.delete('credentials', u.id);
            }, guard);
        },
        async createTenant(input: {
            id?: string;
            data?: Data;
        }, guard?: AdminGuard) {
            const t: TenantRow = { id: input.id === undefined ? id() : identifier(input.id), status: 'active', createdAt: now(), updatedAt: now(), epoch: 1, data: data('tenant', input.data ?? {}) };
            if (t.id === 'default')
                fail('CONFLICT', 'Reserved tenant');
            await tx(w => w.insert('tenants', t), guard);
            return publicTenant(t);
        },
        async getTenant(tenantId = 'default', guard?: AdminGuard) {
            const t = await read(r => r.get('tenants', identifier(tenantId)), guard);
            return t && t.status !== 'deleted' ? publicTenant(t) : undefined;
        },
        async tenantExists(tenantId = 'default') {
            return !!await api.getTenant(tenantId);
        },
        async listTenants(page: ListOptions = {}, guard?: AdminGuard) {
            return (await read(r => r.list('tenants', { limit: page.limit, after: page.after }), guard)).map(publicTenant);
        },
        async updateTenant(tenantId: string, patch: {
            data?: Data;
            status?: 'active' | 'disabled';
        }, guard?: AdminGuard) {
            return tx(async (w) => {
                const t = await get(w, 'tenants', identifier(tenantId));
                if (t.status === 'deleted')
                    fail('NOT_FOUND');
                if (patch.data !== undefined)
                    t.data = data('tenant', patch.data);
                if (patch.status !== undefined) {
                    if (!['active', 'disabled'].includes(patch.status))
                        fail('INVALID_INPUT');
                    if (t.status !== patch.status) {
                        t.status = patch.status;
                        t.epoch = next(t.epoch);
                    }
                }
                t.updatedAt = now();
                await w.put('tenants', t);
                return publicTenant(t);
            }, guard);
        },
        async deleteTenant(tenantId: string, guard?: AdminGuard) {
            if (tenantId === 'default' && defaultEnabled)
                fail('FORBIDDEN');
            await tx(async (w) => {
                const t = await get(w, 'tenants', identifier(tenantId));
                t.status = 'deleted';
                t.epoch = next(t.epoch);
                t.updatedAt = now();
                await w.put('tenants', t);
            }, guard);
        },
        async setClaims(subjectId: string, tenantId: string, claims: readonly string[], guard?: AdminGuard) {
            const uid = identifier(subjectId), tid = identifier(tenantId), c = claimSet(claims);
            return tx(async (w) => {
                const u = await w.get('users', uid) ?? await w.get('services', uid);
                assertActive(u);
                assertActive(await w.get('tenants', tid));
                if (u?.kind === 'service' && u.tenantId !== tid)
                    fail('FORBIDDEN');
                const k = grantId(uid, tid), old = await w.get('grants', k);
                if (!old)
                    await w.insert('grants', { id: k, userId: uid, tenantId: tid, claims: c, revision: 1, incarnation: id(), sessionEpoch: 1 });
                else if (!sameClaims(old.claims, c))
                    await w.put('grants', { ...old, claims: c, revision: next(old.revision) });
                return c;
            }, guard);
        },
        async getClaims(subjectId: string, tenantId = 'default', guard?: AdminGuard) {
            return read(async (r) => (await r.get('grants', grantId(identifier(subjectId), identifier(tenantId))))?.claims, guard);
        },
        async listTenantIds(subjectId: string, page: ListOptions = {}, guard?: AdminGuard) {
            return read(async (r) => (await r.list('grants', { where: { userId: identifier(subjectId) }, limit: page.limit, after: page.after === undefined ? undefined : grantId(identifier(subjectId), identifier(page.after)) })).map(g => g.tenantId), guard);
        },
        async revokeTenantAccess(subjectId: string, tenantId: string, guard?: AdminGuard) {
            await tx(w => w.delete('grants', grantId(identifier(subjectId), identifier(tenantId))), guard);
        },
        async grantClaim(subjectId: string, tenantId: string, claim: string) {
            return tx(async (w) => { const { m } = await state(w, identifier(subjectId), identifier(tenantId), false); const c = claimSet([...m.claims, claim]); if (!sameClaims(m.claims, c))
                await w.put('grants', { ...m, claims: c, revision: next(m.revision) }); return c; });
        },
        async revokeClaim(subjectId: string, tenantId: string, claim: string) {
            return tx(async (w) => { const { m } = await state(w, identifier(subjectId), identifier(tenantId), false); const c = m.claims.filter(x => x !== string(claim, 128)); if (!sameClaims(m.claims, c))
                await w.put('grants', { ...m, claims: c, revision: next(m.revision) }); return c; });
        },
        async hasClaim(userId: string, tenantId: string, claim: string) {
            try {
                return await provider.read(async (r) => (await state(r, identifier(userId), identifier(tenantId), false)).m.claims.includes(claim));
            }
            catch (e) {
                if (e instanceof AuthError && e.code === 'UNAUTHENTICATED')
                    return false;
                throw e;
            }
        }
    };
    return api;
}
