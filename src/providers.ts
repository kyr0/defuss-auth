import { tableNames,type PhysicalTables,type Table } from './records.js';
import { AuthError,fail,integer,string } from './util.js';
export interface ListOptions {
    where?: Record<string, string | number | boolean | null>;
    expiresBefore?: number;
    limit?: number;
    after?: string;
}
export interface ReadStore {
    get<K extends Table>(table: K, id: string): Promise<PhysicalTables[K] | undefined>;
    list<K extends Table>(table: K, options?: ListOptions): Promise<PhysicalTables[K][]>;
}
export interface WriteStore extends ReadStore {
    insert<K extends Table>(table: K, row: PhysicalTables[K]): Promise<void>;
    put<K extends Table>(table: K, row: PhysicalTables[K]): Promise<void>;
    delete<K extends Table>(table: K, id: string): Promise<void>;
}
/** Callback must not perform external side effects; provider may report conflicts, never replay callbacks itself. */
export interface AuthProvider {
    init(): Promise<void>;
    read<T>(fn: (store: ReadStore) => Promise<T>): Promise<T>;
    transaction<T>(fn: (store: WriteStore) => Promise<T>): Promise<T>;
    close(): Promise<void>;
}
const copy = <T>(v: T): T => structuredClone(v);
const limit = (o: ListOptions) => {
    if (o.after !== undefined)
        string(o.after, 512);
    return integer(o.limit ?? 100, 1, 1000);
};
/** Retry only optimistic commit conflicts, not a deterministic duplicate or domain error. */
export class TransactionConflict extends AuthError {
    constructor(cause?: unknown) {
        super('CONFLICT', 'Retryable transaction conflict', { cause });
    }
}
/** In-memory reference provider: serialized writers, copy-on-write maps, snapshot reads. */
export class MemoryProvider implements AuthProvider {
    private tables = new Map<Table, Map<string, unknown>>(tableNames.map(k => [k, new Map()]));
    private tail = Promise.resolve();
    private closed = false;
    async init() {
        if (this.closed)
            fail('UNAVAILABLE');
    }
    private view(tables: Map<Table, Map<string, unknown>>, valid: () => boolean): WriteStore {
        const map = (k: Table) => {
            if (!valid())
                fail('UNAVAILABLE', 'Store scope closed');
            return tables.get(k)!;
        };
        return {
            async get(k, id) {
                return copy(map(k).get(id)) as never;
            }, async list(k, o = {}) {
                return [...map(k).values()].filter(x => {
                    const r = x as Record<string, unknown>;
                    return (!o.after || String(r.id) > o.after) && Object.entries(o.where ?? {}).every(([f, v]) => r[f] === v) && (o.expiresBefore === undefined || typeof r.expiresAt === 'number' && r.expiresAt <= o.expiresBefore);
                }).sort((a, b) => {
                    if (o.expiresBefore !== undefined) {
                        const d = (a as {
                            expiresAt: number;
                        }).expiresAt - (b as {
                            expiresAt: number;
                        }).expiresAt;
                        if (d)
                            return d;
                    }
                    const x = (a as {
                        id: string;
                    }).id, y = (b as {
                        id: string;
                    }).id;
                    return x < y ? -1 : x > y ? 1 : 0;
                }).slice(0, limit(o)).map(copy) as never;
            }, async insert(k, r) {
                if (map(k).has(r.id))
                    fail('CONFLICT');
                await this.put(k, r);
            }, async put(k, r) {
                if (k === 'users') {
                    const email = (r as PhysicalTables['users']).emailCanonical;
                    for (const [other, x] of map(k))
                        if (other !== r.id && (x as PhysicalTables['users']).emailCanonical === email)
                            fail('CONFLICT', 'Email exists');
                }
                map(k).set(r.id, copy(r));
            }, async delete(k, id) {
                map(k).delete(id);
            }
        };
    }
    async read<T>(fn: (r: ReadStore) => Promise<T>): Promise<T> {
        if (this.closed)
            fail('UNAVAILABLE');
        let open = true;
        const v = this.view(this.tables, () => open);
        try {
            return await fn({ get: v.get, list: v.list });
        }
        finally {
            open = false;
        }
    }
    async transaction<T>(fn: (r: WriteStore) => Promise<T>): Promise<T> {
        if (this.closed)
            fail('UNAVAILABLE');
        const prior = this.tail;
        let done!: () => void;
        this.tail = new Promise<void>(r => done = r);
        await prior;
        let open = true;
        try {
            const next = new Map([...this.tables].map(([k, v]) => [k, new Map(v)]));
            const result = await fn(this.view(next, () => open));
            this.tables = next;
            return result;
        }
        finally {
            open = false;
            done();
        }
    }
    async close() {
        this.closed = true;
        await this.tail;
    }
}
/** Structural defuss-db 3.2.0 contract, based on its actual source. No dependency in core or client. */
export interface DbReadCollection {
    get(id: string): Promise<unknown>;
    find(request: unknown): Promise<unknown[]>;
}
export interface DbWriteCollection extends DbReadCollection {
    insert(row: unknown): Promise<unknown>;
    put(row: unknown): Promise<unknown>;
    delete(id: string): Promise<unknown>;
}
export interface DbSnapshot {
    collection(name: string): DbReadCollection;
    close(): Promise<void>;
}
export interface DbTx {
    collection(name: string): DbWriteCollection;
}
export interface DbConnection {
    ensureCollection(name: string, options: {
        $trackHistory: false;
    }): Promise<unknown>;
    collection(name: string): DbWriteCollection & {
        createIndex(def: unknown): Promise<unknown>;
    };
    snapshot(): Promise<DbSnapshot>;
    transaction<T>(fn: (tx: DbTx) => Promise<T>): Promise<{
        result: T;
    }>;
    close(): Promise<void>;
}
const indexes: Partial<Record<Table, {
    name: string;
    fields: string[];
    unique?: boolean;
    order?: ('asc' | 'desc')[];
}[]>> = { users: [{ name: 'email', fields: ['emailCanonical'], unique: true }], grants: [{ name: 'tenantUser', fields: ['tenantId', 'userId'], unique: true }, { name: 'user', fields: ['userId', 'id'] }], sessions: [{ name: 'owner', fields: ['userId', 'tenantId', 'id'] }, { name: 'expiry', fields: ['expiresAt', 'id'] }], apiKeys: [{ name: 'subjectOwner', fields: ['subjectId', 'tenantId', 'id'] }, { name: 'expiry', fields: ['expiresAt', 'id'] }], refresh: [{ name: 'expiry', fields: ['expiresAt', 'id'] }], challenges: [{ name: 'expiry', fields: ['expiresAt', 'id'] }], rates: [{ name: 'expiry', fields: ['expiresAt', 'id'] }], services: [{ name: 'tenant', fields: ['tenantId', 'id'] }], audit: [{ name: 'expiry', fields: ['expiresAt', 'id'] }], keys:[{name:'expiry',fields:['expiresAt','id']}], revocations: [{ name: 'expiry', fields: ['expiresAt', 'id'] }] };
export class DefussDbProvider implements AuthProvider {
    private db: DbConnection;
    constructor(db: unknown, private readonly owned = false, private readonly prefix = 'auth_') {
        this.db = db as DbConnection;
        if (!/^[a-z][a-z0-9_]{0,32}$/.test(prefix))
            fail('INVALID_INPUT', 'Invalid collection prefix');
    }
    async init() {
        for (const k of tableNames) {
            await this.db.ensureCollection(this.prefix + k, { $trackHistory: false });
            for (const def of indexes[k] ?? []) {
                await this.db.collection(this.prefix + k).createIndex(def.unique ? def : { ...def, order: def.fields.map(() => 'asc') });
            }
        }
    }
    private readView(s: {
        collection(name: string): DbReadCollection;
    }): ReadStore {
        const c = (k: Table) => s.collection(this.prefix + k);
        return {
            async get(k, id) {
                return await c(k).get(id) as never;
            }, async list(k, o = {}) {
                const filters: unknown[] = Object.entries(o.where ?? {}).map(([field, value]) => ({ field, op: 'eq', value }));
                if (o.after)
                    filters.push({ field: 'id', op: 'gt', value: o.after });
                if (o.expiresBefore !== undefined)
                    filters.push({ field: 'expiresAt', op: 'lte', value: o.expiresBefore });
                return await c(k).find({ filters, sorters: o.expiresBefore !== undefined ? [{ field: 'expiresAt', direction: 'asc' }, { field: 'id', direction: 'asc' }] : [{ field: 'id', direction: 'asc' }], limit: limit(o) }) as never;
            }
        };
    }
    async read<T>(fn: (r: ReadStore) => Promise<T>): Promise<T> {
        const s = await this.db.snapshot();
        try {
            return await fn(this.readView(s));
        }
        finally {
            await s.close();
        }
    }
    async transaction<T>(fn: (r: WriteStore) => Promise<T>): Promise<T> {
        try {
            return (await this.db.transaction(async (tx) => {
                const r = this.readView(tx);
                const c = (k: Table) => tx.collection(this.prefix + k);
                return fn({
                    ...r, async insert(k, row) {
                        await c(k).insert(row);
                    }, async put(k, row) {
                        await c(k).put(row);
                    }, async delete(k, id) {
                        await c(k).delete(id);
                    }
                });
            })).result;
        }
        catch (e) {
            const code = (e as {
                code?: string;
            })?.code;
            if (code === 'CONFLICT' && !(e instanceof AuthError))
                throw new TransactionConflict(e);
            if (code === 'DUPLICATE_KEY' || code === 'UNIQUE_VIOLATION')
                throw new AuthError('CONFLICT', 'Persistence conflict', { cause: e });
            throw e;
        }
    }
    async close() {
        if (this.owned)
            await this.db.close();
    }
}
