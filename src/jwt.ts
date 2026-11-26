/** Restricted compact JWS/JWT profile. Ed25519 only; legacy EdDSA opt-in. */
import { b64,fail,id,integer,jsonCopy,object,parseJson,sha,string,text,unb64,utf8,type Data } from './util.js';
export type JwtClaims = Data & {
    iss: string;
    aud: string | string[];
    sub: string;
    jti: string;
    iat: number;
    exp: number;
    nbf?: number;
};
export interface JwtPolicy {
    issuer: string;
    audience: string;
    now?: number;
    clockToleranceSec?: number;
    maxTtlSec?: number;
    legacyEdDSA?: boolean;
    typ?: string;
}
export interface JwtHeader {
    alg: 'Ed25519' | 'EdDSA';
    kid: string;
    typ: string;
}
export interface KeyPair {
    kid: string;
    publicJwk: JsonWebKey;
    privateJwk: JsonWebKey;
}
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || unb64(jwk.x, 44).length !== 32)
        fail('INVALID_INPUT', 'Invalid Ed25519 JWK');
    return sha(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }));
}
export async function genEd25519Pair(): Promise<KeyPair> {
    const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey), privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
    const kid = await jwkThumbprint(publicJwk);
    return { kid, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x, kid } as JsonWebKey, privateJwk: { kty: 'OKP', crv: 'Ed25519', x: privateJwk.x, d: privateJwk.d, kid } as JsonWebKey };
}
export async function importPublic(jwk: JsonWebKey, kid: string): Promise<CryptoKey> {
    if (jwk.d !== undefined || await jwkThumbprint(jwk) !== kid)
        fail('INVALID_INPUT', 'Wrong public key');
    return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, 'Ed25519', false, ['verify']);
}
export async function importPrivate(jwk: JsonWebKey, kid: string): Promise<CryptoKey> {
    if (typeof jwk.d !== 'string' || unb64(jwk.d, 44).length !== 32 || await jwkThumbprint(jwk) !== kid)
        fail('INVALID_INPUT', 'Wrong private key');
    return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d }, 'Ed25519', false, ['sign']);
}
function segments(token: string) {
    if (typeof token !== 'string' || token.length > 24000)
        fail('UNAUTHENTICATED');
    const a = token.split('.');
    if (a.length !== 3 || a.some(x => !x))
        fail('UNAUTHENTICATED');
    return a as [
        string,
        string,
        string
    ];
}
function parseHeader(h:string,legacyEdDSA=false,typ='at+jwt'):JwtHeader {
    const v = parseJson(text(unb64(h, 2048)), 2048);
    if (!object(v) || Object.keys(v).some(k => !['alg', 'kid', 'typ'].includes(k)) || !(v.alg === 'Ed25519' || legacyEdDSA && v.alg === 'EdDSA') || v.typ !== typ || typeof v.kid !== 'string' || unb64(v.kid, 44).length !== 32)
        fail('UNAUTHENTICATED', 'Unsupported JWT header');
    return v as unknown as JwtHeader;
}
export function peekHeader(token:string,legacyEdDSA=false,typ='at+jwt'):JwtHeader{return parseHeader(segments(token)[0],legacyEdDSA,typ);}
export async function signJwt(payload: JwtClaims, key: CryptoKey, kid: string, options: {
    legacyEdDSA?: boolean;
    typ?: string;
} = {}): Promise<string> {
    if (key.algorithm.name !== 'Ed25519' || key.type !== 'private' || unb64(kid, 44).length !== 32)
        fail('INVALID_INPUT');
    const p = jsonCopy(payload, 16384);
    const input = b64(utf8(JSON.stringify({ alg: options.legacyEdDSA ? 'EdDSA' : 'Ed25519', typ: options.typ ?? 'at+jwt', kid }))) + '.' + b64(utf8(JSON.stringify(p)));
    const token = input + '.' + b64(new Uint8Array(await crypto.subtle.sign('Ed25519', key, utf8(input))));
    if (token.length > 24000)
        fail('INVALID_INPUT', 'JWT too large');
    return token;
}
/** Parse the protected header exactly once. The signed segments remain private to this closure. */
export function prepareJwt(token:string,legacyEdDSA=false,typ='at+jwt'){
    const parts=segments(token),header=Object.freeze(parseHeader(parts[0],legacyEdDSA,typ));
    return Object.freeze({header,verify:(key:CryptoKey,expectedKid:string,policy:JwtPolicy)=>verifyPrepared(parts,header,key,expectedKid,policy)});
}
export async function verifyJwt(token:string,key:CryptoKey,expectedKid:string,policy:JwtPolicy):Promise<JwtClaims>{
    try{return await prepareJwt(token,policy.legacyEdDSA,policy.typ).verify(key,expectedKid,policy);}catch{fail('UNAUTHENTICATED','Invalid JWT');}
}
async function verifyPrepared(parts:readonly [string,string,string],h:JwtHeader,key:CryptoKey,expectedKid:string,policy:JwtPolicy):Promise<JwtClaims>{
    try {
        if(h.typ!==(policy.typ??'at+jwt')||h.alg!=='Ed25519'&&!(policy.legacyEdDSA&&h.alg==='EdDSA'))fail('UNAUTHENTICATED');
        if (h.kid !== expectedKid || key.algorithm.name !== 'Ed25519' || key.type !== 'public')
            fail('UNAUTHENTICATED');
        const [a, b, c] = parts, sig = unb64(c, 88);
        if (sig.length !== 64 || !await crypto.subtle.verify('Ed25519', key, sig, utf8(a + '.' + b)))
            fail('UNAUTHENTICATED');
        const p = parseJson(text(unb64(b, 22000)), 16384);
        if (!object(p) || p.iss !== policy.issuer || !(p.aud === policy.audience || Array.isArray(p.aud) && p.aud.length > 0 && p.aud.every(x => typeof x === 'string') && p.aud.includes(policy.audience)))
            fail('UNAUTHENTICATED');
        string(p.sub);
        string(p.jti);
        const i = integer(p.iat, 0, Number.MAX_SAFE_INTEGER), e = integer(p.exp, 0, Number.MAX_SAFE_INTEGER), n = policy.now ?? Math.floor(Date.now() / 1000), s = integer(policy.clockToleranceSec ?? 30, 0, 300);
        if (e <= i || e - i > (policy.maxTtlSec ?? 86400) || n >= e + s || i > n + s)
            fail('UNAUTHENTICATED');
        if (p.nbf !== undefined) {
            const nb = integer(p.nbf, 0, Number.MAX_SAFE_INTEGER);
            if (nb >= e || nb > n + s)
                fail('UNAUTHENTICATED');
        }
        return p as JwtClaims;
    }
    catch {
        fail('UNAUTHENTICATED', 'Invalid JWT');
    }
}
export function registeredClaims(issuer: string, audience: string, subject: string, ttlSec: number, now = Math.floor(Date.now() / 1000)): JwtClaims {
    return { iss: issuer, aud: audience, sub: subject, jti: id(), iat: now, exp: now + integer(ttlSec, 1, 86400) };
}
export { unb64 as base64urlDecode,b64 as base64urlEncode };
