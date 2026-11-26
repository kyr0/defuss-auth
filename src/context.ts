/** Internal operation dependencies; the composition root owns all mutable authority state. */
import type { AdminGuard,AuditEvent,AuthOptions,AuthPolicy,Principal,SessionTokens } from './auth.js';
import type { KeyStore } from './keys.js';
import type { PasswordHasher } from './password.js';
import type { AuthorityProvider,AuthReadStore,AuthWriteStore,Compact } from './persistence.js';
import type { Grant,Session,SigningKey,Status,Table,Tables } from './records.js';
import type { SchemaSet } from './schema.js';
import { fail,integer,type Data } from './util.js';
export const sameClaims = (a: unknown, b: readonly string[]) => Array.isArray(a) && a.length === b.length && b.every((c, i) => a[i] === c);
export const next = (n: number) => integer(n + 1, 1, Number.MAX_SAFE_INTEGER);
export function assertActive(r: {
    status: Status;
} | undefined): void { if (!r || r.status !== 'active')
    fail('UNAUTHENTICATED'); }
export interface State {
    u: Compact<'users'> | Compact<'services'>;
    t: Compact<'tenants'>;
    m: Grant;
}
export interface OperationsContext {
    provider: AuthorityProvider;
    keyStore: KeyStore;
    options: AuthOptions;
    configHash: string;
    p: Required<AuthPolicy>;
    now(): number;
    hasher: PasswordHasher;
    dummyHash: string;
    defaultEnabled: boolean;
    autoJoin: boolean;
    data(kind: keyof SchemaSet, value: unknown): Data;
    read<T>(fn: (r: AuthReadStore) => Promise<T>, guard?: AdminGuard): Promise<T>;
    tx<T>(fn: (w: AuthWriteStore) => Promise<T>, guard?: AdminGuard, auditContext?: {
        actorId?: string;
        tenantId?: string;
    } | false): Promise<T>;
    get<K extends Table>(r: AuthReadStore, table: K, k: string): Promise<Tables[K]>;
    state(r: AuthReadStore, userId: string, tenantId: string, verifyEmail?: boolean): Promise<State>;
    matchEpoch(s: {
        incarnation: string;
        userEpoch: number;
        tenantEpoch: number;
    }, st: State): boolean;
    sessionValid(s: Session, st: State, time: number): boolean;
    emit(event: AuditEvent): Promise<void>;
    throttle(kind: string, key: string, limit?: number): Promise<void>;
    signingKey(r: AuthReadStore): Promise<SigningKey>;
    privateCache: Map<string, Promise<CryptoKey>>;
    publicCache: Map<string, Promise<CryptoKey>>;
    issue(r: AuthReadStore, s: Session, st: State, time: number): Promise<{
        accessToken: string;
        expiresAt: number;
    }>;
    newSession(w: AuthWriteStore, st: State, time: number, proofAt?: number): Promise<SessionTokens>;
    checkedProof(r: AuthReadStore, principal: Principal, recent?: boolean): Promise<{
        s: Session;
        st: State;
    }>;
    requirePrincipal(principal: Principal): void;
    authenticate(input: string | Headers | Request, opts?: {
        tenantId?: string;
    }): Promise<Principal>;
    withExclusive<T>(fn: () => Promise<T>): Promise<T>;
}
