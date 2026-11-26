/** Store application-owned data separately from security state. All paired writes share one transaction. */
import type { AuthProvider,ListOptions,ReadStore,WriteStore } from './providers.js';
import type { IdentityTable,PhysicalTables,ServiceRow,Table,Tables,TenantRow,UserRow } from './records.js';
import { fail } from './util.js';
export type Compact<K extends IdentityTable> = Omit<Tables[K], 'data'>;
export interface AuthReadStore {
    get<K extends Table>(table: K, id: string): Promise<Tables[K] | undefined>;
    list<K extends Table>(table: K, options?: ListOptions): Promise<Tables[K][]>;
    getCompact<K extends IdentityTable>(table: K, id: string): Promise<Compact<K> | undefined>;
}
export interface AuthWriteStore extends AuthReadStore {
    insert<K extends Table>(table: K, row: Tables[K]): Promise<void>;
    put<K extends Table>(table: K, row: Tables[K]): Promise<void>;
    delete<K extends Table>(table: K, id: string): Promise<void>;
    putCompact<K extends IdentityTable>(table: K, row: Compact<K>): Promise<void>;
}
export interface AuthorityProvider extends Omit<AuthProvider, 'read' | 'transaction'> {
    read<T>(fn: (store: AuthReadStore) => Promise<T>): Promise<T>;
    transaction<T>(fn: (store: AuthWriteStore) => Promise<T>): Promise<T>;
}
const identity = (k: Table): k is IdentityTable => k === 'users' || k === 'tenants' || k === 'services';
const key = (table: IdentityTable, id: string) => table + ':' + id;
async function hydrate<K extends Table>(r: ReadStore, table: K, row: PhysicalTables[K] | undefined): Promise<Tables[K] | undefined> {
    if (!row || !identity(table))
        return row as Tables[K] | undefined;
    const profile = await r.get('profiles', key(table, row.id));
    if (!profile)
        fail('UNAVAILABLE', 'Identity profile missing');
    return { ...row, data: profile.data } as Tables[K];
}
function reader(r: ReadStore): AuthReadStore {
    return {
        async get(k, id) { return hydrate(r, k, await r.get(k, id)); },
        async list<K extends Table>(k: K, o?: ListOptions): Promise<Tables[K][]> { const rows = await r.list(k, o); if (!identity(k))
            return rows as Tables[K][]; const result: Tables[K][] = []; for (const row of rows)
            result.push((await hydrate(r, k, row))!); return result; },
        async getCompact(k, id) { const row = await r.get(k, id); if (!row)
            return undefined; return row as Compact<typeof k>; }
    };
}
function writer(w: WriteStore): AuthWriteStore {
    async function write<K extends Table>(method: 'insert' | 'put', table: K, row: Tables[K]) {
        if (!identity(table)) {
            await w[method](table, row as PhysicalTables[K]);
            return;
        }
        const { data, ...rest } = row as UserRow | TenantRow | ServiceRow;
        await w[method]('profiles', { id: key(table, row.id), data });
        // The physical provider accepts this storage representation. The public identity interface always hydrates it.
        await w[method](table, rest as PhysicalTables[K]);
    }
    return { ...reader(w), insert: (k, r) => write('insert', k, r), put: (k, r) => write('put', k, r), async delete(k, id) { await w.delete(k, id); if (identity(k))
            await w.delete('profiles', key(k, id)); },
        async putCompact(k, row) { await w.put(k, row as PhysicalTables[typeof k]); }
    };
}
/** Wrap raw providers once; callers of createAuth continue using the original persistence interface. */
export function separateProfiles(provider: AuthProvider): AuthorityProvider {
    return { init: () => provider.init(), close: () => provider.close(), read: fn => provider.read(r => fn(reader(r))), transaction: fn => provider.transaction(w => fn(writer(w))) };
}
