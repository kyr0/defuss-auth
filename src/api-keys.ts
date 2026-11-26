/** api-keys operations: explicit dependencies, no global authority. */
import type { AdminGuard,Principal } from './auth.js';
import { type OperationsContext } from './context.js';
import { publicKey,type ApiKeyRow } from './records.js';
import { claimSet,fail,identifier,integer,opaque,string,tag } from './util.js';
export function createApiKeysOperations(ctx: OperationsContext) {
    const { read, tx, get, state, now, p, matchEpoch, checkedProof, requirePrincipal } = ctx;
    const api = {
        async createApiKey(input: {
            subjectId?: string;
            userId?: string;
            tenantId?: string;
            name: string;
            claims?: string[];
            expiresAt?: number;
        }, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            const uid = identifier(input.subjectId ?? input.userId), name = string(input.name, 128);
            const secret = opaque('dfa_'), digest = await tag('api-key', secret.secret);
            return tx(async (w) => {
                const tid = identifier(input.tenantId ?? (await w.getCompact('services', uid))?.tenantId ?? 'default');
                if (principal) {
                    await checkedProof(w, principal, true);
                    if (principal.subjectId !== uid || principal.tenantId !== tid)
                        fail('FORBIDDEN');
                }
                const time = now(), st = await state(w, uid, tid), claims = claimSet(input.claims ?? st.m.claims);
                if (claims.some(c => !st.m.claims.includes(c)))
                    fail('FORBIDDEN');
                const k: ApiKeyRow = { id: secret.keyId, subjectId: uid, subjectKind: st.u.kind, tenantId: tid, name, claims, createdAt: time, expiresAt: integer(input.expiresAt ?? time + p.apiKeyTtlMs, time + 1, time + p.maxApiKeyTtlMs), revokedAt: null, incarnation: st.m.incarnation, userEpoch: st.u.epoch, tenantEpoch: st.t.epoch, digest };
                await w.insert('apiKeys', k);
                return { apiKey: secret.secret, record: publicKey(k) };
            }, guard, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async getApiKey(keyId: string, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            return read(async (r) => {
                if (principal)
                    await checkedProof(r, principal);
                const k = await r.get('apiKeys', identifier(keyId));
                if (!k || principal && (k.subjectId !== principal.subjectId || k.tenantId !== principal.tenantId))
                    return undefined;
                return publicKey(k);
            }, guard);
        },
        async listApiKeys(input: {
            subjectId?: string;
            userId?: string;
            tenantId?: string;
            limit?: number;
            after?: string;
        }, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            return read(async (r) => {
                const u = identifier(input.subjectId ?? input.userId), t = identifier(input.tenantId ?? (await r.getCompact('services', u))?.tenantId ?? 'default');
                if (principal) {
                    await checkedProof(r, principal);
                    if (principal.subjectId !== u || principal.tenantId !== t)
                        fail('FORBIDDEN');
                }
                return (await r.list('apiKeys', {
                    where: { subjectId: u, tenantId: t }, limit: input.limit, after: input.after
                })).map(publicKey);
            }, guard);
        },
        async updateApiKey(keyId: string, patch: {
            name?: string;
            claims?: string[];
        }, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            return tx(async (w) => {
                if (principal)
                    await checkedProof(w, principal, true);
                const k = await get(w, 'apiKeys', identifier(keyId));
                if (principal && (k.subjectId !== principal.subjectId || k.tenantId !== principal.tenantId))
                    fail('NOT_FOUND');
                if (k.revokedAt !== null)
                    fail('CONFLICT');
                if (patch.name !== undefined)
                    k.name = string(patch.name, 128);
                if (patch.claims !== undefined) {
                    const c = claimSet(patch.claims);
                    if (c.some(x => !k.claims.includes(x)))
                        fail('FORBIDDEN', 'Only scope reduction permitted');
                    k.claims = c;
                }
                await w.put('apiKeys', k);
                return publicKey(k);
            }, guard, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async revokeApiKey(keyId: string, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            await tx(async (w) => {
                if (principal)
                    await checkedProof(w, principal);
                const k = await get(w, 'apiKeys', identifier(keyId));
                if (principal && (k.subjectId !== principal.subjectId || k.tenantId !== principal.tenantId))
                    fail('NOT_FOUND');
                if (k.revokedAt === null) {
                    k.revokedAt = now();
                    await w.put('apiKeys', k);
                }
            }, guard, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        },
        async rotateApiKey(keyId: string, principal?: Principal, guard?: AdminGuard) {
            if (principal)
                requirePrincipal(principal);
            const secret = opaque('dfa_'), digest = await tag('api-key', secret.secret);
            return tx(async (w) => {
                if (principal)
                    await checkedProof(w, principal, true);
                const k = await get(w, 'apiKeys', identifier(keyId));
                if (principal && (k.subjectId !== principal.subjectId || k.tenantId !== principal.tenantId))
                    fail('NOT_FOUND');
                const time = now(), st = await state(w, k.subjectId, k.tenantId);
                if (k.revokedAt !== null || k.expiresAt <= time || !matchEpoch(k, st))
                    fail('CONFLICT');
                const fresh: ApiKeyRow = { ...k, id: secret.keyId, digest, createdAt: time, expiresAt: p.apiKeyRotationTtlMs ? time + p.apiKeyRotationTtlMs : Math.min(k.expiresAt, time + p.maxApiKeyTtlMs), claims: k.claims.filter(c => st.m.claims.includes(c)) };
                k.revokedAt = time;
                await w.put('apiKeys', k);
                await w.insert('apiKeys', fresh);
                return { apiKey: secret.secret, record: publicKey(fresh) };
            }, guard, principal ? { actorId: principal.subjectId, tenantId: principal.tenantId } : undefined);
        }
    };
    return api;
}
