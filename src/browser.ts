/** Browser-local authority, not a security boundary. OPFS requires a secure dedicated worker. */
import { createAuth as createCore,type Auth,type AuthOptions } from './auth.js';
import { StorageKeyStore,type MasterKeyRing } from './keys.js';
import { createPbkdf2Hasher } from './password.js';
import { DefussDbProvider } from './providers.js';
import type { SchemaSet } from './schema.js';
import { fail } from './util.js';
export interface BrowserOptions<S extends SchemaSet=SchemaSet> extends Omit<AuthOptions<S>, 'provider' | 'keyStore' | 'passwordHasher' | 'ownProvider'> {
    insecureLocalAuthority: true;
    encryptionKey?: Uint8Array;
    keyRing?: MasterKeyRing;
    namespace?: string;
    dbOptions?: Parameters<typeof import('defuss-db/browser').openOPFS>[0];
    keyStorageOptions?: Parameters<typeof import('defuss-storage/opfs').createOPFSStorage>[0];
    passwordHasher?: AuthOptions['passwordHasher'];
}
export async function createAuth<const S extends SchemaSet=SchemaSet>(options: BrowserOptions<S>):Promise<Auth<S>> {
    if (options.insecureLocalAuthority !== true || !globalThis.isSecureContext)
        fail('INVALID_INPUT', 'Explicit local authority and secure context required');
    // Destructured only to keep the browser-only flag out of the core options. VERIFIED: AuthOptions defines no such field.
    const { insecureLocalAuthority: _insecureLocalAuthority, encryptionKey, keyRing, namespace = 'defuss-auth', dbOptions, keyStorageOptions, passwordHasher, ...rest } = options;
    if (!keyRing && (!(encryptionKey instanceof Uint8Array) || encryptionKey.length !== 32))
        fail('INVALID_INPUT', '32-byte encryption key required');
    const [{ openOPFS }, { createOPFSStorage }] = await Promise.all([import('defuss-db/browser'), import('defuss-storage/opfs')]);
    const db = await openOPFS({ ...dbOptions, namespace: namespace + '-db', name: 'auth' });
    const provider = new DefussDbProvider(db, true);
    try {
        const storage = await createOPFSStorage({ ...keyStorageOptions, name: namespace + '-keys' });
        return await createCore<S>({ ...rest, provider, keyStore: new StorageKeyStore({ storage, ...(keyRing?{keyRing}:{encryptionKey}) }), passwordHasher: passwordHasher ?? createPbkdf2Hasher(), ownProvider: true });
    }
    catch (e) {
        await provider.close().catch(() => {
        });
        throw e;
    }
}
