import * as crypto from 'node:crypto';
import type { PasswordHasher } from './password.js';
import { b64,fail,random,tag,unb64,utf8,verifyTag } from './util.js';
interface ArgonParams {
    message: Uint8Array;
    nonce: Uint8Array;
    memory: number;
    passes: number;
    parallelism: number;
    tagLength: number;
}
type ArgonFn = (alg: 'argon2id', params: ArgonParams, cb: (err: Error | null, result: Uint8Array) => void) => void;
const standard = (bytes: Uint8Array) => b64(bytes).replace(/-/g, '+').replace(/_/g, '/');
const decode = (s: string) => unb64(s.replace(/\+/g, '-').replace(/\//g, '_'), 256);
/** Native asynchronous Argon2id, PHC v19. No silent KDF downgrade. */
export function createArgon2Hasher(): PasswordHasher {
    const native = (crypto as unknown as {
        argon2?: ArgonFn;
    }).argon2;
    const bun = (globalThis as unknown as {
        Bun?: {
            password?: {
                hash: (p: string, o: {
                    algorithm: 'argon2id';
                    memoryCost: number;
                    timeCost: number;
                }) => Promise<string>;
                verify: (p: string, h: string) => Promise<boolean>;
            };
        };
    }).Bun?.password;
    if (!native && !bun)
        fail('UNAVAILABLE', 'Native Argon2id requires Node >=24.7 or Bun; provide an explicit hasher');
    const parse = (encoded: string) => {
        const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded);
        if (!m)
            return undefined;
        const memory = Number(m[1]), passes = Number(m[2]), parallelism = Number(m[3]);
        if (!Number.isSafeInteger(memory) || memory < 19456 || memory > 131072 || !Number.isSafeInteger(passes) || passes < 2 || passes > 6 || !Number.isSafeInteger(parallelism) || parallelism < 1 || parallelism > 4)
            return undefined;
        const nonce = decode(m[4]!), result = decode(m[5]!);
        if (nonce.length < 16 || nonce.length > 32 || result.length !== 32)
            return undefined;
        return { memory, passes, parallelism, nonce, result };
    };
    async function derive(p: string, nonce: Uint8Array, memory: number, passes: number, parallelism: number) {
        if (!native)
            fail('UNAVAILABLE');
        return new Promise<Uint8Array>((resolve, reject) => native('argon2id', { message: utf8(p), nonce, memory, passes, parallelism, tagLength: 32 }, (e, r) => e ? reject(e) : resolve(new Uint8Array(r))));
    }
    return {
        needsRehash: h=> {const v=parse(h);return !!v&&(v.memory<65536||v.passes<3);},
        async hash(p) {
            if (!native) {
                const h = await bun!.hash(p, { algorithm: 'argon2id', memoryCost: 65536, timeCost: 3 });
                if (!parse(h))
                    fail('UNAVAILABLE', 'Unexpected native PHC profile');
                return h;
            }
            const nonce = random(16);
            return `$argon2id$v=19$m=65536,t=3,p=1$${standard(nonce)}$${standard(await derive(p, nonce, 65536, 3, 1))}`;
        }, async verify(p, encoded) {
            const m = parse(encoded);
            if (!m)
                return false;
            if (!native)
                return bun!.verify(p, encoded);
            const result = await derive(p, m.nonce, m.memory, m.passes, m.parallelism);
            return verifyTag('kdf-compare', b64(result), await tag('kdf-compare', b64(m.result)));
        }
    };
}
