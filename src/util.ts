/** Stable error codes. Internal causes are deliberately not serialized by HTTP adapters. */
export type ErrorCode = 'INVALID_INPUT' | 'UNAUTHENTICATED' | 'FORBIDDEN' | 'NOT_FOUND' | 'CONFLICT' | 'SCHEMA' | 'RATE_LIMIT' | 'UNAVAILABLE';
export class AuthError extends Error {
    constructor(readonly code: ErrorCode, message: string = code, options?: ErrorOptions) {
        super(message, options);
        this.name = 'AuthError';
    }
}
export function fail(code: ErrorCode, message?: string): never {
    throw new AuthError(code, message);
}
export const utf8 = (v: string) => new TextEncoder().encode(v);
export const text = (v: Uint8Array) => new TextDecoder('utf-8', { fatal: true }).decode(v);
export const random = (size: number) => crypto.getRandomValues(new Uint8Array(size));
export const id = () => crypto.randomUUID();
type Base64Array=Uint8Array & {toBase64?:(options:{alphabet:'base64url';omitPadding:boolean})=>string};
const fromBase64=(Uint8Array as unknown as {fromBase64?:(input:string,opts:{alphabet:'base64url';lastChunkHandling:'loose'})=>Uint8Array}).fromBase64;
export function b64(v: Uint8Array): string {
    if(typeof (v as Base64Array).toBase64==='function')return (v as Base64Array).toBase64!({alphabet:'base64url',omitPadding:true});
    let s = '';
    for (const byte of v)
        s += String.fromCharCode(byte);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64(v: string, max = 65536): Uint8Array {
    if (typeof v !== 'string' || v.length > max || !/^[A-Za-z0-9_-]*$/.test(v) || v.length % 4 === 1)
        fail('INVALID_INPUT', 'Invalid base64url');
    const a = fromBase64?fromBase64.call(Uint8Array,v,{alphabet:'base64url',lastChunkHandling:'loose'}):Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    if (b64(a) !== v)
        fail('INVALID_INPUT', 'Noncanonical base64url');
    return a;
}
export const sha = async (v: string | Uint8Array) => b64(new Uint8Array(await crypto.subtle.digest('SHA-256', typeof v === 'string' ? utf8(v) : v)));
export type Json = null | boolean | number | string | Json[] | {
    [key: string]: Json;
};
export type Data = {
    [key: string]: Json;
};
export function object(v: unknown): v is Record<string, unknown> {
    return !!v && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
}
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
/** Strict JSON, no coercion, duplicate keys, prototype keys or unbounded nesting. */
export function parseJson(s: string, max = 65536): Json {
    if (s.length > max)
        fail('INVALID_INPUT', 'JSON too large');
    let i = 0;
    const ws = () => {
        while (i < s.length && /[\x20\t\n\r]/.test(s[i]!))
            i++;
    };
    const bad = (): never => fail('INVALID_INPUT', 'Invalid JSON');
    function str(): string {
        const start = i++;
        while (i < s.length) {
            const c = s[i++]!;
            if (c === '\\') {
                i++;
                continue;
            }
            if (c === '"') {
                try {
                    return JSON.parse(s.slice(start, i));
                }
                catch {
                    return bad();
                }
            }
        }
        return bad();
    }
    function value(depth: number): Json {
        if (depth > 32)
            return bad();
        ws();
        const c = s[i];
        if (c === '"')
            return str();
        if (c === '{') {
            i++;
            const o: Data = Object.create(null);
            ws();
            if (s[i] === '}') {
                i++;
                return o;
            }
            while (true) {
                ws();
                if (s[i] !== '"')
                    return bad();
                const k = str();
                if (forbidden.has(k) || Object.hasOwn(o, k))
                    return bad();
                ws();
                if (s[i++] !== ':')
                    return bad();
                o[k] = value(depth + 1);
                ws();
                const end = s[i++];
                if (end === '}')
                    return o;
                if (end !== ',')
                    return bad();
            }
        }
        if (c === '[') {
            i++;
            const a: Json[] = [];
            ws();
            if (s[i] === ']') {
                i++;
                return a;
            }
            while (true) {
                a.push(value(depth + 1));
                ws();
                const end = s[i++];
                if (end === ']')
                    return a;
                if (end !== ',')
                    return bad();
            }
        }
        for (const [k, v] of [['true', true], ['false', false], ['null', null]] as const)
            if (s.startsWith(k, i)) {
                i += k.length;
                return v;
            }
        const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(s.slice(i));
        if (!m)
            return bad();
        i += m[0].length;
        const n = Number(m[0]);
        return Number.isFinite(n) ? n : bad();
    }
    const v = value(0);
    ws();
    if (i !== s.length)
        return bad();
    return v;
}
/** Validate caller-owned data without invoking getters or toJSON. */
export function jsonCopy(v: unknown, max = 65536): Json {
    const seen = new Set<object>();
    let budget = max;
    function visit(x: unknown, d: number): Json {
        if (--budget < 0 || d > 32)
            fail('INVALID_INPUT', 'JSON budget exceeded');
        if (x === null || typeof x === 'boolean')
            return x;
        if (typeof x === 'string') {
            budget -= x.length;
            if (budget < 0)
                fail('INVALID_INPUT', 'JSON budget exceeded');
            return x;
        }
        if (typeof x === 'number' && Number.isFinite(x))
            return x;
        if (!Array.isArray(x) && !object(x))
            fail('INVALID_INPUT', 'Expected JSON');
        if (seen.has(x))
            fail('INVALID_INPUT', 'Cyclic JSON');
        seen.add(x);
        const descriptors = Object.getOwnPropertyDescriptors(x);
        const out: Data = Object.create(null);
        for (const k of Object.keys(descriptors)) {
            if (Array.isArray(x) && k === 'length')
                continue;
            const a = descriptors[k]!;
            if (forbidden.has(k) || !('value' in a) || !a.enumerable)
                fail('INVALID_INPUT', 'Invalid JSON property');
            budget -= k.length;
            out[k] = visit(a.value, d + 1);
        }
        if (Object.getOwnPropertySymbols(x).length)
            fail('INVALID_INPUT', 'Symbol property');
        seen.delete(x);
        if (Array.isArray(x)) {
            if (Object.keys(out).length !== x.length || x.length > max)
                fail('INVALID_INPUT', 'Sparse or extended array');
            return Array.from({ length: x.length }, (_, i) => {
                if (!Object.hasOwn(out, String(i)))
                    fail('INVALID_INPUT', 'Sparse array');
                return out[String(i)]!;
            });
        }
        return out;
    }
    const r = visit(v, 0);
    if (utf8(JSON.stringify(r)).length > max)
        fail('INVALID_INPUT', 'JSON too large');
    return r;
}
export function dataCopy(v: unknown): Data {
    const x = jsonCopy(v);
    if (!object(x))
        fail('INVALID_INPUT', 'Expected data object');
    return x as Data;
}
export function freeze<T>(v: T): T {
    if (v && typeof v === 'object' && !Object.isFrozen(v)) {
        for (const x of Object.values(v))
            freeze(x);
        Object.freeze(v);
    }
    return v;
}
export function string(v: unknown, max = 256): string {
    // Control characters are rejected on purpose: they enable log and header injection.
    // VERIFIED: test 'names, claims and emails reject control characters'.
    // oxlint-disable-next-line no-control-regex
    if (typeof v !== 'string' || !v.length || v.length > max || /[\x00-\x1f\x7f]/.test(v))
        fail('INVALID_INPUT', 'Invalid string');
    return v;
}
export function integer(v: unknown, min: number, max: number): number {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max)
        fail('INVALID_INPUT', 'Invalid integer');
    return v;
}
export function identifier(v: unknown): string {
    const s = string(v, 128);
    if (!/^[A-Za-z0-9_-]+$/.test(s))
        fail('INVALID_INPUT', 'Invalid identifier');
    return s;
}
export function claimSet(v: unknown): string[] {
    if (!Array.isArray(v) || v.length > 256)
        fail('INVALID_INPUT', 'Invalid claims');
    return [...new Set(v.map(c => string(c, 128)))].sort();
}
export function canonicalEmail(v: unknown): string {
    const s = string(v, 254).trim().toLowerCase();
    if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]+$/.test(s) || s.includes('..') || s.split('@')[0]!.length > 64 || s.startsWith('.') || s.includes('.@'))
        fail('INVALID_INPUT', 'Invalid ASCII email');
    return s;
}
export function password(v: unknown, min = 15): string {
    if (typeof v !== 'string' || v.length > 1024 || utf8(v).length > 1024 || [...v].length < min)
        fail('INVALID_INPUT', 'Invalid password length');
    return v;
}
export type Authorization = {
    scheme: 'bearer' | 'apiKey';
    token: string;
};
export function parseAuthorization(input: string | Headers | Request): Authorization {
    const h = typeof input === 'string' ? input : input instanceof Request ? input.headers.get('authorization') : input.get('authorization');
    if (!h || h.length > 24000)
        fail('UNAUTHENTICATED');
    const m = /^(Bearer|ApiKey) +([A-Za-z0-9_.-]+)$/i.exec(h);
    if (!m)
        fail('UNAUTHENTICATED');
    return { scheme: m[1]!.toLowerCase() === 'bearer' ? 'bearer' : 'apiKey', token: m[2]! };
}
/** High-entropy opaque secrets: a public domain-separated HMAC key, native tag verification. No password use. */
const tagKeys = new Map<string,Promise<CryptoKey>>();
function tagKey(purpose:string) {
    let k=tagKeys.get(purpose);if(k)return k;
    k=crypto.subtle.importKey('raw',utf8('defuss-auth/v1/'+purpose),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
    if(tagKeys.size<32){tagKeys.set(purpose,k);void k.catch(()=>{if(tagKeys.get(purpose)===k)tagKeys.delete(purpose);});}return k;
}
export async function tag(purpose: string, secret: string): Promise<string> {
    return b64(new Uint8Array(await crypto.subtle.sign('HMAC', await tagKey(purpose), utf8(secret))));
}
export async function verifyTag(purpose: string, secret: string, digest: string): Promise<boolean> {
    const d = unb64(digest, 64);
    return d.length === 32 && crypto.subtle.verify('HMAC', await tagKey(purpose), d, utf8(secret));
}
export function opaque(prefix: string) {
    const keyId = id();
    return { keyId, secret: prefix + keyId + '.' + b64(random(32)) };
}
export function opaqueId(prefix: string, value: string): string {
    if (typeof value !== 'string' || value.length > 160 || !value.startsWith(prefix))
        fail('UNAUTHENTICATED');
    const [k, s, ...rest] = value.slice(prefix.length).split('.');
    if (!k || !s || rest.length || !/^[a-f0-9-]{36}$/.test(k) || unb64(s, 44).length !== 32)
        fail('UNAUTHENTICATED');
    return k;
}
