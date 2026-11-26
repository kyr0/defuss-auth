/** lifecycle operations: explicit dependencies, no global authority. */
import { type OperationsContext } from './context.js';
import { genEd25519Pair } from './jwt.js';
import { type SigningKey } from './records.js';
import { AuthError,fail,integer } from './util.js';
export function createLifecycleOperations(ctx: OperationsContext) {
    const { provider, tx, get, now, p, keyStore, signingKey, privateCache, publicCache, withExclusive } = ctx;
    const api = {
        async jwks() {
            return provider.read(async (r) => {
                const keys: SigningKey[] = [];
                let after: string | undefined;
                for (;;) {
                    const batch = await r.list('keys', { limit: 1000, after });
                    keys.push(...batch.filter(k => k.state === 'active' || k.state === 'retired' && k.verifyUntil > now()));
                    if (batch.length < 1000)
                        break;
                    after = batch.at(-1)!.id;
                }
                return { keys: keys.filter(k => k.state === 'active' || k.state === 'retired' && k.verifyUntil > now()).map(k => ({ ...k.publicJwk, kid: k.id, use: 'sig', alg: 'Ed25519' })) };
            });
        },
        async rotateSigningKey(input: {
            revokePrevious?: boolean;
            expectedKid?: string;
        } = {}) {
            const pair = await genEd25519Pair();
            await keyStore.save(pair);
            await tx(async (w) => {
                const meta = await get(w, 'meta', 'authority'), old = await get(w, 'keys', meta.activeKid);
                if (input.expectedKid && meta.activeKid !== input.expectedKid)
                    fail('CONFLICT', 'Signing key already rotated');
                old.state = input.revokePrevious ? 'revoked' : 'retired';
                old.verifyUntil = now() + (86400 + 300 + 1) * 1000;
                old.expiresAt = old.verifyUntil;
                await w.put('keys', old);
                await w.insert('keys', { id: pair.kid, publicJwk: pair.publicJwk, state: 'active', createdAt: now(), verifyUntil: Number.MAX_SAFE_INTEGER, expiresAt: Number.MAX_SAFE_INTEGER });
                meta.activeKid = pair.kid;
                await w.put('meta', meta);
            });
            return pair.kid;
        },
        async rewrapSigningKey() {
            if (!keyStore.rewrap)
                fail('UNAVAILABLE', 'Key store does not support re-encryption');
            const k = await provider.read(signingKey), generation = await keyStore.rewrap(k.id, k.storageGeneration);
            await tx(async (w) => { const current = await signingKey(w); if (current.id !== k.id || current.storageGeneration !== k.storageGeneration)
                fail('CONFLICT', 'Signing key changed'); await w.put('keys', { ...current, storageGeneration: generation }); });
            privateCache.clear();
            return { kid: k.id, generation };
        },
        async reconcileKeyFiles(input: {
            exclusive: true;
            limit?: number;
        }) {
            if (input.exclusive !== true || !keyStore.reconcile)
                fail('FORBIDDEN', 'Exclusive key maintenance required');
            return withExclusive(async () => {
                const k = await provider.read(signingKey);
                // Retired keys only need their public JWKs. Keep the active private generation.
                return await keyStore.reconcile!([{ kid: k.id, generation: k.storageGeneration }], integer(input.limit ?? 100, 1, 1000));
            });
        },
        async revokeSigningKey(kid: string) {
            await tx(async (w) => {
                const meta = await get(w, 'meta', 'authority');
                if (kid === meta.activeKid)
                    fail('CONFLICT', 'Rotate active key first');
                const k = await get(w, 'keys', kid);
                k.state = 'revoked';
                k.expiresAt = now();
                await w.put('keys', k);
            });
            for (const cacheKey of privateCache.keys())
                if (cacheKey.startsWith(kid + ":"))
                    privateCache.delete(cacheKey);
            publicCache.delete(kid);
        },
        async cleanup(limit = 100) {
            integer(limit, 1, 1000);
            return tx(async (w) => {
                let n = 0;
                for (const k of ['revocations', 'rates', 'challenges', 'refresh', 'apiKeys', 'sessions'] as const) {
                    const rows = await w.list(k, { expiresBefore: now(), limit });
                    for (const row of rows) {
                        await w.delete(k, row.id);
                        n++;
                    }
                }
                const oldKeys = await w.list('keys', { expiresBefore: now(), limit });
                for (const k of oldKeys)
                    if (k.state !== 'active') {
                        await w.delete('keys', k.id);
                        n++;
                    }
                const audits = await w.list('audit', { expiresBefore: now(), limit });
                for (const row of audits) {
                    await w.delete('audit', row.id);
                    n++;
                }
                return n;
            }, undefined, false);
        },
        async maintain(limit = 100) { const k = await provider.read(signingKey); let rotated = false; if (now() - k.createdAt >= p.signingKeyMaxAgeMs) {
            try {
                await api.rotateSigningKey({ expectedKid: k.id });
                rotated = true;
            }
            catch (e) {
                if (!(e instanceof AuthError && e.code === 'CONFLICT'))
                    throw e;
            }
        } return { rotated, removed: await api.cleanup(limit) }; }
    };
    return api;
}
