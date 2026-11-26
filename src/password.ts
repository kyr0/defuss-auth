import { b64,fail,integer,random,tag,unb64,utf8,verifyTag } from './util.js';
export interface PasswordHasher {
    hash(password: string): Promise<string>;
    needsRehash?(encoded:string):boolean;
    verify(password: string, encoded: string): Promise<boolean>;
}
/** Bound native KDF concurrency and queue length to avoid unbounded memory consumption. */
export function boundedHasher(inner: PasswordHasher, concurrency = 2, queueLimit = 16): PasswordHasher {
    integer(concurrency, 1, 32);
    integer(queueLimit, 0, 1024);
    let running = 0;
    const queue: Array<() => void> = [];
    async function run<T>(fn: () => Promise<T>): Promise<T> {
        if (running >= concurrency) {
            if (queue.length >= queueLimit)
                fail('RATE_LIMIT');
            await new Promise<void>(r => queue.push(r));
        }
        else
            running++;
        try {
            return await fn();
        }
        finally {
            const next = queue.shift();
            if (next)
                next();
            else
                running--;
        }
    }
    return {
        needsRehash: inner.needsRehash?.bind(inner), hash: p => run(() => inner.hash(p)), verify: (p, h) => run(() => inner.verify(p, h))
    };
}
export function createPbkdf2Hasher(iterations = 600000): PasswordHasher {
    integer(iterations, 600000, 2000000);
    async function derive(p: string, s: Uint8Array, n: number) {
        const k = await crypto.subtle.importKey('raw', utf8(p), 'PBKDF2', false, ['deriveBits']);
        return b64(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: s, iterations: n }, k, 256)));
    }
    return {
        needsRehash: h=> Number(h.split('$')[2])<iterations,
        async hash(p) {
            const s = random(16);
            return `$pbkdf2-sha256$${iterations}$${b64(s)}$${await derive(p, s, iterations)}`;
        }, async verify(p, h) {
            const m = /^\$pbkdf2-sha256\$(\d+)\$([\w-]+)\$([\w-]+)$/.exec(h);
            if (!m)
                return false;
            const n = Number(m[1]);
            if (!Number.isSafeInteger(n) || n < 600000 || n > 2000000)
                return false;
            const s = unb64(m[2]!, 64), d = unb64(m[3]!, 64);
            if (s.length !== 16 || d.length !== 32)
                return false;
            return verifyTag('kdf-compare', await derive(p, s, n), await tag('kdf-compare', m[3]!));
        }
    };
}
