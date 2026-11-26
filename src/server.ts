/** Native persistent defaults. Imports platform-specific modules only in this entry point. */
import { lstat,mkdir,open,realpath } from 'node:fs/promises';
import { join,resolve } from 'node:path';
import { createAuth as createCore,type Auth,type AuthOptions } from './auth.js';
import { StorageKeyStore,type MasterKeyRing } from './keys.js';
import { createArgon2Hasher } from './native-password.js';
import { DefussDbProvider } from './providers.js';
import type { SchemaSet } from './schema.js';
import { fail,unb64 } from './util.js';
export { createArgon2Hasher };
export interface ServerOptions<S extends SchemaSet=SchemaSet> extends Omit<AuthOptions<S>, 'provider' | 'keyStore' | 'passwordHasher' | 'ownProvider'> {
    provider?: AuthOptions['provider'];
    keyStore?: AuthOptions['keyStore'];
    passwordHasher?: AuthOptions['passwordHasher'];
    ownProvider?: boolean;
    storage?: {
        directory?: string;
        db?: Parameters<typeof import('defuss-db/server').openDirectory>[1];
        keys?: Parameters<typeof import('defuss-storage/node').createFileStorage>[1];
        collectionPrefix?: string;
    };
    encryptionKey?: Uint8Array;
    keyRing?: MasterKeyRing;
}
async function privateDirectory(path: string) {
    const dir = resolve(path);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const info = await lstat(dir);
    // Every component, not only the last: a symlinked ancestor could later point the authority at other files.
    // VERIFIED: macOS tmpdir() is /var/folders/…, a path through the /var symlink, so callers pass its realpath.
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(dir) !== dir)
        fail('UNAVAILABLE', 'Auth storage must be a real directory on a canonical path; pass its realpath');
    if (process.platform !== 'win32' && (info.mode & 0o077) !== 0)
        fail('UNAVAILABLE', 'Auth storage directory must be owner-only (0700)');
    if (typeof process.getuid === 'function' && info.uid !== process.getuid())
        fail('UNAVAILABLE', 'Unexpected directory owner');
    return dir;
}
export async function createAuth<const S extends SchemaSet=SchemaSet>(options: ServerOptions<S>):Promise<Auth<S>> {
    const { storage = {}, encryptionKey, keyRing, ...rest } = options;
    const passwordHasher = rest.passwordHasher ?? createArgon2Hasher();
    const directory = storage.directory ?? './data/auth';
    let provider = rest.provider, keyStore = rest.keyStore, owned = rest.ownProvider ?? false;
    try {
        if (!keyStore) {
            const master = encryptionKey ?? (process.env.DEFUSS_AUTH_MASTER_KEY ? unb64(process.env.DEFUSS_AUTH_MASTER_KEY, 44) : undefined);
            if (!keyRing && (!master || master.length !== 32))
                fail('INVALID_INPUT', 'Provide 32-byte encryptionKey or DEFUSS_AUTH_MASTER_KEY');
            const root = await privateDirectory(directory), keysDir = await privateDirectory(join(root, 'keys'));
            const { createFileStorage } = await import('defuss-storage/node');
            const bytes = await createFileStorage(keysDir, storage.keys);
            keyStore = new StorageKeyStore({
                storage: bytes, ...(keyRing?{keyRing}:{encryptionKey:master}), syncDirectory: async () => {
                    const handle = await open(keysDir, 'r');
                    try {
                        await handle.sync();
                    }
                    finally {
                        await handle.close();
                    }
                }
            });
        }
        if (!provider) {
            const root = await privateDirectory(directory), dbDir = await privateDirectory(join(root, 'db'));
            const { openDirectory } = await import('defuss-db/server');
            const db = await openDirectory(dbDir, {
                name: 'auth', parallel: false, storage: { scanWorkers: 0 }, ...storage.db
            });
            provider = new DefussDbProvider(db, true, storage.collectionPrefix);
            owned = true;
        }
        return await createCore<S>({ ...rest, provider, keyStore, passwordHasher, ownProvider: owned });
    }
    catch (e) {
        if (owned)
            await provider?.close().catch(() => {
            });
        throw e;
    }
}
