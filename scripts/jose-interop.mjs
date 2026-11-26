/** Independent JOSE implementation, development-only. Legacy EdDSA is explicitly enabled for interoperability. */
import assert from 'node:assert/strict';
import {SignJWT,importJWK,jwtVerify,calculateJwkThumbprint} from 'jose';
import {genEd25519Pair,importPrivate,importPublic,registeredClaims,signJwt,verifyJwt} from 'defuss-auth/jwt';
const pair=await genEd25519Pair(),priv=await importPrivate(pair.privateJwk,pair.kid),pub=await importPublic(pair.publicJwk,pair.kid);
const policy={issuer:'interop',audience:'interop',legacyEdDSA:true};
assert.equal(pair.kid,await calculateJwkThumbprint(pair.publicJwk));
const claims=registeredClaims('interop','interop','interop-user',60);
const token=await signJwt(claims,priv,pair.kid,{legacyEdDSA:true});
const external=await jwtVerify(token,await importJWK(pair.publicJwk,'EdDSA'),{issuer:'interop',audience:'interop',algorithms:['EdDSA']});
assert.equal(external.payload.sub,claims.sub);
const signed=await new SignJWT(claims).setProtectedHeader({alg:'EdDSA',typ:'at+jwt',kid:pair.kid}).sign(await importJWK(pair.privateJwk,'EdDSA'));
assert.equal((await verifyJwt(signed,pub,pair.kid,policy)).jti,claims.jti);
await assert.rejects(()=>verifyJwt(signed,pub,pair.kid,{issuer:'interop',audience:'interop'}));
console.log('JOSE EdDSA interoperability passed',process.version);
