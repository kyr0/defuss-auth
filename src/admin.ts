/** admin operations: explicit dependencies, no global authority. */
import type { AdminGuard,AdminOperation,Principal } from './auth.js';
import { type OperationsContext } from './context.js';
import type { AuthReadStore } from './persistence.js';
import type { ListOptions } from './providers.js';
import { grantId,publicKey } from './records.js';
import { canonicalEmail,fail,freeze } from './util.js';
export function createAdminOperations(ctx: OperationsContext) {
    const { provider, configHash, requirePrincipal, checkedProof } = ctx;
    const api = {
        async prepareAdmin(principal: Principal, operation: AdminOperation, authorize: (p: Principal, op: AdminOperation & {
            target?: unknown;
        }) => boolean | Promise<boolean>): Promise<AdminGuard> {
            requirePrincipal(principal);
            operation = freeze(structuredClone(operation));
            const target = async (r: AuthReadStore) => {
                const k = operation.id;
                const table = operation.resource.startsWith('users') ? 'users' : operation.resource.startsWith('services') ? 'services' : operation.resource.startsWith('tenants') ? 'tenants' : undefined;
                const row = table && k ? await r.get(table, k) : undefined;
                const t = table === 'services' && row && 'tenantId' in row && typeof row.tenantId === 'string' ? row.tenantId : operation.tenantId;
                if (operation.tenantId && t && operation.tenantId !== t)
                    fail('FORBIDDEN');
                if ((operation.resource === 'users/claims' || operation.resource === 'services/claims') && (!row || row.status === 'deleted'))
                    fail('NOT_FOUND');
                if (operation.resource === 'services/api-keys' && (!row || !t))
                    fail('NOT_FOUND');
                const key = operation.keyId ? await r.get('apiKeys', operation.keyId) : undefined;
                if (operation.keyId && (!key || key.subjectId !== k || key.tenantId !== t))
                    fail('NOT_FOUND');
                const invitation = operation.resource === 'invitations' && k ? await r.get('challenges', k) : undefined;
                if (invitation && (invitation.kind !== 'invite' || operation.tenantId && invitation.tenantId !== operation.tenantId))
                    fail('NOT_FOUND');
                const actualTenant = invitation?.tenantId ?? t;
                const recipientEmail = operation.resource === 'invitations' && operation.method === 'POST' || operation.resource === 'users' && operation.method === 'POST' ? canonicalEmail(operation.body.email) : undefined;
                const recipient = recipientEmail ? (await r.list('users', { where: { emailCanonical: recipientEmail }, limit: 1 }))[0] : undefined;
                const defaultTenant = operation.resource === 'users' && operation.method === 'POST' ? await r.get('tenants', 'default') : undefined;
                return { row, recipient, defaultTenant, tenantId: actualTenant, tenant: actualTenant ? await r.get('tenants', actualTenant) : undefined, grant: k && actualTenant ? await r.get('grants', grantId(k, actualTenant)) : undefined, key: key ? publicKey(key) : undefined, invitation: invitation ? { id: invitation.id, tenantId: invitation.tenantId, email: invitation.email, claims: invitation.claims, used: invitation.used, expiresAt: invitation.expiresAt } : undefined,
                    actor: await r.get('users', principal.subjectId), actorTenant: await r.get('tenants', principal.tenantId) };
            };
            const initial = await provider.read(async (r) => { await checkedProof(r, principal, true); return target(r); });
            const snapshot = JSON.stringify(initial);
            if (!await authorize(principal, freeze({ ...operation, tenantId: initial.tenantId, target: initial })))
                fail('FORBIDDEN');
            return Object.freeze(Object.assign(async (r: AuthReadStore) => { await checkedProof(r, principal, true); if (JSON.stringify(await target(r)) !== snapshot)
                fail('CONFLICT', 'Authorization target changed'); }, { actorId: principal.subjectId, tenantId: initial.tenantId ?? principal.tenantId }));
        },
        configurationFingerprint: async () => configHash,
        async listAudit(page: ListOptions = {}) { return provider.read(r => r.list('audit', page)); },
        /** At-least-once delivery; caller persists the returned cursor only after its sink succeeds. */
        async deliverAudit(input: {
            after?: string;
            limit?: number;
            deliver: (event: Readonly<import('./records.js').AuditRow>) => Promise<void>;
        }) {
            const rows = await provider.read(r => r.list('audit', { after: input.after, limit: input.limit }));
            let after = input.after;
            for (const row of rows) {
                await input.deliver(freeze(row));
                after = row.id;
            }
            return { after, delivered: rows.length };
        }
    };
    return api;
}
