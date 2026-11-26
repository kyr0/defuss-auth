/** Allowlisted, secret-free projections for durable security audit records. */
import type { Table } from './records.js';
import type { Data,Json } from './util.js';
const fields: Partial<Record<Table, readonly string[]>> = {
    users: ['status', 'emailVerified', 'epoch', 'sessionEpoch'], tenants: ['status', 'epoch'], services: ['status', 'tenantId', 'epoch'],
    grants: ['userId', 'tenantId', 'claims', 'revision', 'incarnation', 'sessionEpoch'],
    credentials: ['version'], sessions: ['userId', 'tenantId', 'createdAt', 'expiresAt', 'idleUntil', 'revokedAt', 'proofAt'],
    refresh: ['sid', 'used', 'expiresAt'], apiKeys: ['subjectId', 'subjectKind', 'tenantId', 'claims', 'expiresAt', 'revokedAt'],
    challenges: ['kind', 'userId', 'tenantId', 'used', 'expiresAt'], keys: ['state', 'verifyUntil', 'storageGeneration'], meta: ['activeKid', 'schemaHash', 'configHash', 'format'], revocations: ['expiresAt']
};
export function auditProjection(table: Table, record: unknown): Data | undefined {
    if (!record || typeof record !== 'object')
        return undefined;
    const out: Data = {};
    for (const k of fields[table] ?? []) {
        const v = (record as Record<string, unknown>)[k];
        if (v !== undefined)
            out[k] = structuredClone(v) as Json;
    }
    return out;
}
