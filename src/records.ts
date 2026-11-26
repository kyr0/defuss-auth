import type { Data } from './util.js';
export type Status = 'active' | 'disabled' | 'deleted';
export interface User<T extends Data = Data> {
    id: string;
    email: string;
    emailVerified: boolean;
    status: Status;
    createdAt: number;
    updatedAt: number;
    data: T;
}
export interface Tenant<T extends Data = Data> {
    id: string;
    status: Status;
    createdAt: number;
    updatedAt: number;
    data: T;
}
/** Tenant access is an authorization primitive, not an application membership record. */
export interface Grant {
    id: string;
    userId: string;
    tenantId: string;
    claims: string[];
    revision: number;
    incarnation: string;
    sessionEpoch: number;
}
export interface UserRow extends User {
    kind: 'user';
    epoch: number;
    sessionEpoch: number;
    emailCanonical: string;
}
export interface ServiceAccount<T extends Data = Data> {
    id: string;
    tenantId: string;
    name: string;
    status: Status;
    createdAt: number;
    updatedAt: number;
    data: T;
}
export interface ServiceRow extends ServiceAccount {
    kind: 'service';
    epoch: number;
    sessionEpoch: number;
}
export interface TenantRow extends Tenant {
    epoch: number;
}
export interface Credential {
    id: string;
    hash: string;
    version: string;
}
export interface Session {
    id: string;
    userId: string;
    tenantId: string;
    incarnation: string;
    userEpoch: number;
    tenantEpoch: number;
    userSessionEpoch: number;
    grantSessionEpoch: number;
    createdAt: number;
    expiresAt: number;
    idleUntil: number;
    revokedAt: number | null;
    proofAt: number;
}
export interface RefreshRow {
    id: string;
    sid: string;
    digest: string;
    expiresAt: number;
    used: boolean;
}
export interface ApiKey {
    id: string;
    subjectId: string;
    subjectKind: 'user' | 'service';
    tenantId: string;
    name: string;
    claims: string[];
    createdAt: number;
    expiresAt: number;
    revokedAt: number | null;
}
export interface ApiKeyRow extends ApiKey {
    incarnation: string;
    userEpoch: number;
    tenantEpoch: number;
    digest: string;
}
export interface Challenge {
    id: string;
    kind: 'reset' | 'verify' | 'login' | 'invite' | 'register';
    tenantId?: string;
    claims?: string[];
    tenantEpoch?: number;
    grantIncarnation?: string;
    registrationData?: Data;
    userId: string;
    email: string;
    epoch: number;
    credentialVersion: string | null;
    digest: string;
    expiresAt: number;
    used: boolean;
}
export interface SigningKey {
    id: string;
    publicJwk: JsonWebKey;
    storageGeneration?: string;
    state: 'active' | 'retired' | 'revoked';
    createdAt: number;
    verifyUntil: number;
    expiresAt: number;
}
export interface Meta {
    id: string;
    issuer: string;
    audience: string;
    schemaHash: string;
    activeKid: string;
    format: 2;
    configHash: string;
}
export interface Revocation {
    id: string;
    expiresAt: number;
}
export interface Rate {
    id: string;
    count: number;
    expiresAt: number;
}
export interface Tables {
    users: UserRow;
    tenants: TenantRow;
    profiles: ProfileRow;
    grants: Grant;
    services: ServiceRow;
    audit: AuditRow;
    auditState: {
        id: string;
        sequence: number;
    };
    credentials: Credential;
    sessions: Session;
    refresh: RefreshRow;
    apiKeys: ApiKeyRow;
    challenges: Challenge;
    keys: SigningKey;
    meta: Meta;
    revocations: Revocation;
    rates: Rate;
}
export type IdentityTable = 'users' | 'tenants' | 'services';
/** Actual persisted rows. User/tenant/service application data lives in profiles. */
export type PhysicalTables = {
    [K in keyof Tables]: K extends IdentityTable ? Omit<Tables[K], 'data'> : Tables[K];
};
export type Table = keyof Tables;
export const tableNames: Table[] = ['users', 'tenants', 'profiles', 'grants', 'services', 'audit', 'auditState', 'credentials', 'sessions', 'refresh', 'apiKeys', 'challenges', 'keys', 'meta', 'revocations', 'rates'];
export const grantId = (userId: string, tenantId: string) => JSON.stringify([tenantId, userId]);
export function publicUser(r: UserRow): User {
    const { id, email, emailVerified, status, createdAt, updatedAt, data } = r;
    return { id, email, emailVerified, status, createdAt, updatedAt, data };
}
export function publicTenant(r: TenantRow): Tenant {
    const { id, status, createdAt, updatedAt, data } = r;
    return { id, status, createdAt, updatedAt, data };
}
export function publicService(r: ServiceRow): ServiceAccount {
    const { id, tenantId, name, status, createdAt, updatedAt, data } = r;
    return { id, tenantId, name, status, createdAt, updatedAt, data };
}
export interface ProfileRow {
    id: string;
    data: Data;
}
export interface AuditRow {
    id: string;
    at: number;
    expiresAt: number;
    changes: {
        table: string;
        id: string;
        action: 'insert' | 'put' | 'delete';
        before?: Data;
        after?: Data;
    }[];
    actorId?: string;
    tenantId?: string;
}
export function publicKey(r: ApiKeyRow): ApiKey {
    const { id, subjectId, subjectKind, tenantId, name, claims, createdAt, expiresAt, revokedAt } = r;
    return { id, subjectId, subjectKind, tenantId, name, claims, createdAt, expiresAt, revokedAt };
}
