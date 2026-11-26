// Gate for the real defuss-db + defuss-storage packages, not the offline bridge.
import assert from 'node:assert/strict';
import {mkdtemp,realpath,rm,mkdir,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {createAuth,createArgon2Hasher} from 'defuss-auth/server';
// Canonical path. VERIFIED: storage rejects symlinked ancestors such as macOS /var -> /private/var.
const dir=await realpath(await mkdtemp(join(tmpdir(),'defuss-auth-native-')));
const encryptionKey=Uint8Array.from(randomBytes(32));
const cfg={issuer:'https://native.example.test',audience:'native-e2e',storage:{directory:dir},encryptionKey};
const password='native test long password';
let auth;
try{
  auth=await createAuth(cfg);
  const results=await Promise.allSettled(Array.from({length:4},()=>auth.createUser({email:'unique@example.test',password})));
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  const u=results.find(x=>x.status==='fulfilled').value;
  await auth.grantClaim(u.id,'default','read');
  const session=await auth.login({email:u.email,password});
  const key=await auth.createApiKey({userId:u.id,name:'native',claims:['read']});
  assert((await auth.authenticate('Bearer '+session.accessToken)).hasClaim('read'));
  await auth.close();auth=await createAuth(cfg);
  assert((await auth.authenticate('ApiKey '+key.apiKey)).hasClaim('read'));
  assert((await auth.authenticate('Bearer '+session.accessToken)).hasClaim('read'));
  const both=await Promise.allSettled([auth.refresh(session.refreshToken),auth.refresh(session.refreshToken)]);
  assert.equal(both.filter(x=>x.status==='fulfilled').length,1);
  await assert.rejects(()=>auth.authenticate('Bearer '+both.find(x=>x.status==='fulfilled').value.accessToken));
  const service=await auth.createServiceAccount({name:'native-worker',claims:['read']});const serviceKey=await auth.createApiKey({subjectId:service.id,name:'worker'});assert.equal((await auth.authenticate('ApiKey '+serviceKey.apiKey)).subjectKind,'service');
  await auth.rotateSigningKey();await auth.revokeApiKey(key.record.id);await assert.rejects(()=>auth.authenticate('ApiKey '+key.apiKey));
  const nextKey=Uint8Array.from(randomBytes(32));await auth.close();auth=await createAuth({...cfg,encryptionKey:undefined,keyRing:{activeVersion:'next',keys:{legacy:encryptionKey,next:nextKey}}});await auth.rewrapSigningKey();await auth.reconcileKeyFiles({exclusive:true});await auth.close();auth=await createAuth({...cfg,encryptionKey:undefined,keyRing:{activeVersion:'next',keys:{next:nextKey}}});assert((await auth.authenticate('ApiKey '+serviceKey.apiKey)).hasClaim('read'));
  await auth.close();auth=undefined;
  await assert.rejects(()=>createAuth({...cfg,encryptionKey:new Uint8Array(32)}));
  // Node and Bun PHC interchange: make verify runs this script Node first, then Bun.
  await mkdir('output',{recursive:true});const platform=globalThis.Bun?'bun':'node';const hasher=createArgon2Hasher();const hash=await hasher.hash(password);
  if(platform==='bun')assert(await hasher.verify(password,await readFile('output/argon-node.phc','utf8')));
  else {try{const prior=await readFile('output/argon-bun.phc','utf8');assert(await hasher.verify(password,prior));}catch(e){if(e.code!=='ENOENT')throw e;}}
  await writeFile(`output/argon-${platform}.phc`,hash);
  await writeFile(`output/native-${platform}.json`,JSON.stringify({passed:true,runtime:process.version,platform}));
  console.log(`Native ${platform}: passed`);
}finally{await auth?.close();await rm(dir,{recursive:true,force:true});}
