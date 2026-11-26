import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthHost,tenantAdmin} from '../build/test/host.js';
import {AuthError} from '../build/test/index.js';
import {MemoryProvider} from '../build/test/providers.js';
import {MemoryKeyStore} from '../build/test/keys.js';
import {tag,verifyTag} from '../build/test/util.js';
const password='a sufficiently long password';
const hasher={hash:async p=>'test:'+await tag('test-only',p),verify:async(p,h)=>h.startsWith('test:')&&verifyTag('test-only',p,h.slice(5))};
const SECRET='host-credential-secret-0123456789';
const app=(name,o={})=>({issuer:'https://'+name+'.apps.test',audience:name,provider:new MemoryProvider(),keyStore:new MemoryKeyStore(),passwordHasher:hasher,...o});
const host=(o={})=>createAuthHost({directory:'/nonexistent-host-root',credential:{header:'X-Host-Key',secret:SECRET},...o});
const rejects=(f,code)=>assert.rejects(f,e=>e instanceof AuthError&&e.code===code);
const call=(h,path,{body,headers={},method=body===undefined?'GET':'POST',key=SECRET}={})=>h.fetch(new Request('http://127.0.0.1/apps'+path,{method,headers:{...(key?{'x-host-key':key}:{}),...(body===undefined?{}:{'content-type':'application/json'}),...headers},body:body===undefined?undefined:JSON.stringify(body)}));
const login=async(h,name,email,extra={})=>call(h,'/'+name+'/auth/login',{body:{email,password,...extra.body},headers:extra.headers});
/** The throttle bucket of a key, as auth.ts derives it: base64url SHA-256, first two characters. */
const bucket=async(kind,key)=>Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(kind+'\0'+key))).toString('base64url').slice(0,2);
async function distinct(kind,make,n){const out=[],seen=new Set();for(let i=0;out.length<n;i++){const v=make(i),b=await bucket(kind,v);if(!seen.has(b)){seen.add(b);out.push(v);}}return out;}

test('host routes each app under its name and refuses unknown apps, paths and names', async()=>{
 const h=await host();const a=await h.open('alpha',{...app('alpha'),http:{mode:'token'}}),b=await h.open('beta',{...app('beta'),http:{mode:'token'}});
 await a.createUser({email:'ann@example.test',password});await b.createUser({email:'ann@example.test',password:password+' b'});
 assert.equal((await login(h,'alpha','ann@example.test')).status,200);
 assert.equal((await login(h,'beta','ann@example.test')).status,401);           // same email, separate accounts
 assert.equal((await (await call(h,'/alpha/.well-known/jwks.json')).json()).keys.length,1);
 for(const path of ['/gamma/auth/me','/alpha','/alpha/','/ALPHA/auth/me','/alpha/auth/unknown'])assert.equal((await call(h,path)).status,404,path);
 assert.equal((await h.fetch(new Request('http://127.0.0.1/other/alpha/auth/me'))).status,404);
 assert.deepEqual(h.apps(),['alpha','beta']);
 for(const name of ['Alpha','','-x','a/b','..','a'.repeat(65)])await rejects(()=>h.open(name,app('x')),'INVALID_INPUT');
 await rejects(()=>h.open('alpha',app('alpha')),'CONFLICT');
 await rejects(()=>h.open('nokey',{...app('nokey'),keyStore:undefined}),'INVALID_INPUT');
 await h.closeAll();assert.deepEqual(h.apps(),[]);
});

test('host requires the proxy credential and validates its configuration', async()=>{
 const h=await host();const a=await h.open('alpha',{...app('alpha'),http:{mode:'token'}});await a.createUser({email:'ann@example.test',password});
 for(const key of [null,'wrong-credential-secret-value',SECRET+'x'])assert.equal((await call(h,'/alpha/auth/login',{body:{email:'ann@example.test',password},key})).status,403);
 assert.equal((await call(h,'/unknown/auth/me',{key:null})).status,403);   // without the credential, app names stay hidden
 for(const header of ['authorization','Cookie','origin','x-forwarded-for','bad header','x-defuss-csrf'])await rejects(()=>createAuthHost({directory:'/x',credential:{header,secret:SECRET}}),'INVALID_INPUT');
 await rejects(()=>createAuthHost({directory:'/x',credential:{header:'x-key',secret:'short'}}),'INVALID_INPUT');
 for(const basePath of ['apps','/apps/','/a/../b','/a b'])await rejects(()=>createAuthHost({directory:'/x',basePath}),'INVALID_INPUT');
 await rejects(()=>createAuthHost({directory:'/x',masterKey:new Uint8Array(32),keyRing:{activeVersion:'v1',keys:{v1:new Uint8Array(32)}}}),'INVALID_INPUT');
 await h.closeAll();
});

test('host derives rate keys from the forwarded client of a credentialed proxy only', async()=>{
 const policy={rateAttempts:1};const emails=await distinct('login-account',i=>'u'+i+'@example.test',14);
 const [x,y]=await distinct('login-source',i=>'ip:198.51.100.'+i,2);const ip=k=>k.slice(3);
 const h=await host();await h.open('alpha',{...app('alpha',{policy}),http:{mode:'token'}});await h.open('hops',{...app('hops',{policy}),http:{mode:'token'},forwardedHops:1});
 const fails=async(name,mails,xff)=>{const out=[];for(const email of mails)out.push((await login(h,name,email,{headers:{'x-forwarded-for':xff}})).status);return out;};
 // A source may try 5 times per window (rateAttempts * 5); a different source is unaffected.
 assert.deepEqual(await fails('alpha',emails.slice(0,6),'203.0.113.1, '+ip(x)),[401,401,401,401,401,429]);
 assert.equal((await login(h,'alpha',emails[6],{headers:{'x-forwarded-for':ip(y)}})).status,401);
 // One trusted hop: the client is the entry left of the app's own proxy peer.
 assert.deepEqual(await fails('hops',emails.slice(7,13),ip(x)+', 127.0.0.1'),[401,401,401,401,401,429]);
 // Without a credential, nobody vouches for the field, so it is ignored.
 const open=await createAuthHost({directory:'/x'});await open.open('alpha',{...app('alpha',{policy}),http:{mode:'token'}});
 const statuses=[];for(const email of emails.slice(0,7))statuses.push((await call(open,'/alpha/auth/login',{key:null,body:{email,password},headers:{'x-forwarded-for':ip(x)}})).status);
 assert.deepEqual(statuses,Array(7).fill(401));
 await Promise.all([h.closeAll(),open.closeAll()]);
});

test('host.authenticate projects live JWT and API key principals bound to a tenant', async()=>{
 const h=await host();const a=await h.open('alpha',{...app('alpha'),http:{mode:'token'}});
 const u=await a.createUser({email:'ann@example.test',password});await a.createTenant({id:'vector'});await a.setClaims(u.id,'vector',['member']);
 const t=await (await login(h,'alpha','ann@example.test',{body:{tenantId:'vector'}})).json();
 assert.deepEqual(await h.authenticate('alpha','Bearer '+t.accessToken,{tenantId:'vector',claims:['member']}),{app:'alpha',subjectId:u.id,subjectKind:'user',tenantId:'vector',claims:['member'],method:'jwt',credentialId:(await h.authenticate('alpha','Bearer '+t.accessToken)).credentialId,sessionId:t.sessionId});
 await rejects(()=>h.authenticate('alpha','Bearer '+t.accessToken,{tenantId:'default'}),'UNAUTHENTICATED');
 await rejects(()=>h.authenticate('alpha','Bearer '+t.accessToken,{claims:['admin']}),'FORBIDDEN');
 await rejects(()=>h.authenticate('beta','Bearer '+t.accessToken),'NOT_FOUND');
 const s=await a.createServiceAccount({tenantId:'vector',name:'agent',claims:['member']}),k=await a.createApiKey({subjectId:s.id,name:'mcp',claims:['member']});
 const p=await h.authenticate('alpha','ApiKey '+k.apiKey,{tenantId:'vector'});assert.deepEqual([p.subjectKind,p.method,p.sessionId,p.claims],['service','apiKey',null,['member']]);
 await a.revokeApiKey(k.record.id);await rejects(()=>h.authenticate('alpha','ApiKey '+k.apiKey),'UNAUTHENTICATED');
 await a.setClaims(u.id,'vector',[]);await rejects(()=>h.authenticate('alpha','Bearer '+t.accessToken),'UNAUTHENTICATED');   // a grant change revokes live
 await rejects(()=>h.authenticate('alpha','x'.repeat(9000)),'INVALID_INPUT');
 for(const claims of ['member',[1],{length:1}])await rejects(()=>h.authenticate('alpha','Bearer '+t.accessToken,{claims}),'INVALID_INPUT');
 assert.deepEqual(Object.keys(await h.maintain()),['alpha']);
 assert.equal(await h.close('alpha'),true);assert.equal(await h.close('alpha'),false);assert.equal(h.get('alpha'),undefined);
 assert.equal((await call(h,'/alpha/auth/me')).status,404);
});

test('host keeps the refresh cookie on the path the app proxy mounts', async()=>{
 const origin='http://127.0.0.1:8080';const h=await host();
 const a=await h.open('alpha',{...app('alpha'),http:{mode:'cookie',allowedOrigins:[origin]}});await a.createUser({email:'ann@example.test',password});
 const b=await h.open('beta',{...app('beta'),http:{mode:'cookie',allowedOrigins:[origin],prefix:'/api/session'}});await b.createUser({email:'ann@example.test',password});
 const csrf={origin,'x-defuss-csrf':'1'};
 assert.equal((await login(h,'alpha','ann@example.test')).status,403);           // cookie mode still needs Origin and CSRF
 assert.match((await login(h,'alpha','ann@example.test',{headers:csrf})).headers.get('set-cookie'),/; Path=\/auth;/);
 assert.match((await call(h,'/beta/api/session/login',{body:{email:'ann@example.test',password},headers:csrf})).headers.get('set-cookie'),/; Path=\/api\/session;/);
 await h.closeAll();
});

test('tenantAdmin lets an administrator act only inside the tenant that holds the claim', async()=>{
 const h=await host();const a=await h.open('alpha',{...app('alpha'),http:{mode:'token',authorizeAdmin:tenantAdmin('admin')}});
 const u=await a.createUser({email:'ann@example.test',password}),bob=await a.createUser({email:'bob@example.test',password});
 await a.createTenant({id:'acme'});await a.setClaims(u.id,'acme',['admin']);
 const other=await a.createServiceAccount({tenantId:'default',name:'theirs'});
 const t=await (await login(h,'alpha','ann@example.test',{body:{tenantId:'acme'}})).json(),auth={authorization:'Bearer '+t.accessToken};
 const admin=(path,o={})=>call(h,'/alpha/auth/admin'+path,{...o,headers:{...auth,...o.headers}});
 assert.equal((await admin('/services?tenantId=acme',{body:{name:'worker',claims:['admin']}})).status,201);
 assert.equal((await admin('/users/'+bob.id+'/claims/acme',{method:'PUT',body:{claims:['member']}})).status,200);
 assert.equal((await admin('/services?tenantId=default',{body:{name:'x'}})).status,403);
 assert.equal((await admin('/services/'+other.id+'?tenantId=acme')).status,403);        // the service's real tenant decides
 assert.equal((await admin('/users')).status,403);assert.equal((await admin('/users/'+bob.id)).status,403);
 assert.equal((await admin('/tenants/acme',{method:'DELETE'})).status,403);
 await a.setClaims(u.id,'default',[]);const d=await (await login(h,'alpha','ann@example.test')).json();
 assert.equal((await call(h,'/alpha/auth/admin/services?tenantId=default',{body:{name:'x'},headers:{authorization:'Bearer '+d.accessToken}})).status,403);
 const plugin=h.plugin();assert.deepEqual([plugin.name,plugin.routes],['defuss-auth-host',[{path:'/apps',prefix:true}]]);
 await plugin.close();assert.deepEqual(h.apps(),[]);
});
