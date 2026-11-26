import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuth,AuthError,SchemaValidationError} from '../build/test/index.js';
import {MemoryProvider} from '../build/test/providers.js';
import {MemoryKeyStore,StorageKeyStore} from '../build/test/keys.js';
import {createAuthHandler} from '../build/test/serve.js';
import {createAuthClient} from '../build/test/client.js';
import {tag,verifyTag} from '../build/test/util.js';
import {prepareJwt} from '../build/test/jwt.js';
const password='a sufficiently long password';
const hasher={hash:async p=>'test:'+await tag('test-only',p),verify:async(p,h)=>h.startsWith('test:')&&verifyTag('test-only',p,h.slice(5))};
const cfg=(o={})=>({issuer:'https://auth.example.test',audience:'test',provider:new MemoryProvider(),keyStore:new MemoryKeyStore(),passwordHasher:hasher,...o});
const bearer=t=>'Bearer '+t.accessToken, key=t=>'ApiKey '+t.apiKey;
const rejects=(f,code)=>assert.rejects(f,e=>e instanceof AuthError&&e.code===code);
const createUser=(a,email='alice@example.test',data={})=>a.createUser({email,password,data});
const login=(a,u,tenantId='default')=>a.login({email:u.email,password,tenantId});
const handler=(a,o={})=>createAuthHandler(a,{mode:'token',...o});
const req=(path,t,body,method='POST')=>new Request('https://auth.example.test/auth'+path,{method,headers:{...(t?{authorization:bearer(t)}:{}),...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};

test('admin claim revocation during authorization callback prevents write',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a);await a.setClaims(u.id,'default',['admin']);const t=await login(a,u),entered=deferred(),release=deferred();
 const h=handler(a,{authorizeAdmin:async p=>{entered.resolve();await release.promise;return p.hasClaim('admin');}});
 const pending=h.fetch(req('/admin/tenants',t,{id:'must-not-exist'}));await entered.promise;await a.revokeClaim(u.id,'default','admin');release.resolve();
 assert.equal((await pending).status,401);assert.equal(await a.tenantExists('must-not-exist'),false);await a.close();
});
test('admin target change while policy awaits is rejected transactionally',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a),v=await createUser(a,'target@example.test',{allowed:true});const t=await login(a,u),entered=deferred(),release=deferred();
 const h=handler(a,{authorizeAdmin:async(_p,op)=>{assert.equal(op.target.row.data.allowed,true);entered.resolve();await release.promise;return true;}});
 const pending=h.fetch(req('/admin/users/'+v.id,t,{data:{allowed:true}},'PATCH'));await entered.promise;await a.updateUser(v.id,{data:{allowed:false}});release.resolve();
 assert.equal((await pending).status,409);assert.deepEqual((await a.getUser(v.id)).data,{allowed:false});await a.close();
});
test('principal carries only effective claims; raw compact state excludes application data',async()=>{
 const provider=new MemoryProvider(),a=await createAuth(cfg({provider})),u=await createUser(a,'alice@example.test',{private:'never in principal'});
 await a.setClaims(u.id,'default',['admin','read']);const k=await a.createApiKey({subjectId:u.id,name:'limited',claims:['read']}),p=await a.authenticate(key(k));
 assert.deepEqual(p.claims,['read']);assert(!p.hasClaim('admin'));for(const name of ['membership','grant','user','tenant','data'])assert(!(name in p));
 assert.equal((await p.getUser()).data.private,'never in principal');assert.equal((await p.getTenant()).id,'default');
 await provider.read(async r=>{assert(!('data' in await r.get('users',u.id)));assert.equal((await r.list('profiles')).length,2);});
 const h=handler(a);const me=await h.fetch(new Request('https://auth.example.test/auth/me',{headers:{authorization:key(k)}}));assert.equal(me.status,200);assert(!JSON.stringify(await me.json()).includes('never in principal'));
 await a.revokeClaim(u.id,'default','read');await rejects(()=>p.getUser(),'UNAUTHENTICATED');assert.deepEqual((await a.authenticate(key(k))).claims,[]);await a.close();
});
test('client captures original identity before response-body cancellation permits login',async()=>{
 let n=0,replays=[],cancelled=deferred(),c;const fetcher=async(url,init)=>{
 const path=new URL(url).pathname;
 if(path.endsWith('/login')){n++;return Response.json({accessToken:n===1?'A.a.a':'B.b.b',refreshToken:'refresh',expiresAt:Date.now()+100000,sessionId:'s'+n});}
 if(path.endsWith('/refresh'))return Response.json({accessToken:'A.rotated.a',refreshToken:'rotated',expiresAt:Date.now()+100000,sessionId:'s1'});
 const credential=init.headers.get('authorization');replays.push(credential);
 if(replays.length===1)return new Response(new ReadableStream({cancel:async()=>{await c.login({email:'b@example.test',password});cancelled.resolve();}}),{status:401});
 return new Response(null,{status:200});};
 c=createAuthClient({baseUrl:'https://auth.example.test/auth',mode:'token',fetch:fetcher});await c.login({email:'a@example.test',password});assert.equal((await c.fetch('/resource')).status,200);await cancelled.promise;assert.deepEqual(replays,['Bearer A.a.a','Bearer A.rotated.a']);
});
test('service accounts are email-free, tenant-bound and key-scoped',async()=>{
 const a=await createAuth(cfg());await a.createTenant({id:'other'});const s=await a.createServiceAccount({tenantId:'other',name:'worker',claims:['read','write'],data:{machine:true}});
 assert(!('email' in s));assert.deepEqual(await a.listTenantIds(s.id),['other']);await rejects(()=>a.setClaims(s.id,'default',['read']),'FORBIDDEN');
 const k=await a.createApiKey({subjectId:s.id,name:'ci',claims:['read']}),p=await a.requireAuth(key(k),{tenantId:'other',claims:['read']});assert.equal(p.subjectKind,'service');assert.equal(await p.getUser(),undefined);assert.deepEqual((await p.getServiceAccount()).data,{machine:true});await rejects(()=>a.authenticate(key(k),{tenantId:'default'}),'UNAUTHENTICATED');
 await rejects(()=>a.createApiKey({subjectId:s.id,name:'new'},p),'FORBIDDEN');await a.updateServiceAccount(s.id,{status:'disabled'});await rejects(()=>a.authenticate(key(k)),'UNAUTHENTICATED');await a.updateServiceAccount(s.id,{status:'active'});await rejects(()=>a.authenticate(key(k)),'UNAUTHENTICATED');await a.deleteServiceAccount(s.id);assert.equal(await a.getServiceAccount(s.id),undefined);await a.close();
});
test('HTTP admin service key owner cannot be substituted through another URL',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a),t=await login(a,u);const h=handler(a,{authorizeAdmin:()=>true});const c=createAuthClient({baseUrl:'https://auth.example.test/auth',mode:'token',fetch:(u,i)=>h.fetch(new Request(u,i))});await c.login({email:u.email,password});
 const s=await c.admin.createServiceAccount({name:'one',claims:['read']}),other=await c.admin.createServiceAccount({name:'two',claims:['read']});const k=await a.createApiKey({subjectId:s.id,name:'one'});
 assert.equal((await h.fetch(req(`/admin/services/${other.id}/api-keys/${k.record.id}`,t,undefined,'DELETE'))).status,404);
 assert.equal((await h.fetch(req(`/admin/users/${s.id}/claims/default`,t,{claims:['write']},'PUT'))).status,404);
 assert((await a.authenticate(key(k))).hasClaim('read'));assert.equal((await h.fetch(req(`/admin/services/${s.id}/api-keys`,t,undefined,'GET'))).status,200);await a.close();
});
test('verified email gate, passwordless proof and step-up session replacement',async()=>{
 const deliveries=[],a=await createAuth(cfg({passwordless:true,delivery:async x=>deliveries.push(x),policy:{requireVerifiedEmail:true}})),u=await createUser(a);
 await rejects(()=>login(a,u),'UNAUTHENTICATED');await a.requestPasswordlessLogin({email:u.email});const token=deliveries.at(-1).token;
 const t=await a.confirmPasswordlessLogin(token),p=await a.authenticate(bearer(t));assert.equal((await p.getUser()).emailVerified,true);await rejects(()=>a.confirmPasswordlessLogin(token),'UNAUTHENTICATED');
 await rejects(()=>a.createApiKey({subjectId:u.id,name:'no'},p),'FORBIDDEN');const fresh=await a.stepUp(p,password);await rejects(()=>a.authenticate(bearer(t)),'UNAUTHENTICATED');const k=await a.createApiKey({subjectId:u.id,name:'yes'},await a.authenticate(bearer(fresh)));assert.equal(k.record.subjectKind,'user');await a.close();
});
test('passwordless challenge cannot survive revoked and recreated tenant access',async()=>{
 const deliveries=[],a=await createAuth(cfg({passwordless:true,delivery:async e=>deliveries.push(e)})),u=await createUser(a);await a.requestPasswordlessLogin({email:u.email});const token=deliveries.at(-1).token;await a.revokeTenantAccess(u.id,'default');await a.setClaims(u.id,'default',[]);await rejects(()=>a.confirmPasswordlessLogin(token),'UNAUTHENTICATED');await a.close();
});
test('registration policy, email proof, atomic single-use and no password takeover',async()=>{
 let allowed=true;const deliveries=[],a=await createAuth(cfg({delivery:async e=>deliveries.push(e),registration:({email})=>allowed&&email.endsWith('@example.test')}));
 await a.requestRegistration({email:'no@other.test'});assert.equal(deliveries.length,0);
 await a.requestRegistration({email:'new@example.test',data:{name:'New'}});assert.equal(await a.getUserByEmail('new@example.test'),undefined);const token=deliveries.at(-1).token;
 allowed=false;await rejects(()=>a.confirmRegistration({token,password}),'FORBIDDEN');allowed=true;const rs=await Promise.allSettled([a.confirmRegistration({token,password}),a.confirmRegistration({token,password})]);assert.equal(rs.filter(r=>r.status==='fulfilled').length,1);
 const u=await a.getUserByEmail('new@example.test');assert(u.emailVerified);assert.deepEqual(u.data,{name:'New'});assert.deepEqual(await a.getClaims(u.id,'default'),[]);await login(a,u);
 const count=deliveries.length;await a.requestRegistration({email:u.email});assert.equal(deliveries.length,count);await a.close();
});
test('invitations bind tenant and claims; existing user cannot have password or profile overwritten',async()=>{
 const ds=[],a=await createAuth(cfg({delivery:async e=>ds.push(e)})),u=await createUser(a,'old@example.test',{name:'Old'});await a.createTenant({id:'team'});
 await a.inviteToTenant({email:u.email,tenantId:'team',claims:['read']});const token=ds.at(-1).token;
 await rejects(()=>a.acceptInvitation({token,password:'different long password',data:{name:'New'}}),'CONFLICT');await a.acceptInvitation({token});assert.deepEqual(await a.getClaims(u.id,'team'),['read']);assert.deepEqual((await a.getUser(u.id)).data,{name:'Old'});assert((await a.authenticate(bearer(await login(a,u,'team')))).hasClaim('read'));await rejects(()=>a.acceptInvitation({token}),'UNAUTHENTICATED');
 const i=await a.inviteToTenant({email:'new@example.test',tenantId:'team'});await a.revokeInvitation(i.id);await rejects(()=>a.acceptInvitation({token:ds.at(-1).token,password}),'UNAUTHENTICATED');
 await a.inviteToTenant({email:'new@example.test',tenantId:'team',claims:['write']});const r=await a.acceptInvitation({token:ds.at(-1).token,password,data:{name:'New'}});assert.deepEqual(await a.getClaims(r.userId,'team'),['write']);assert.equal((await a.getUser(r.userId)).emailVerified,true);await a.close();
});
test('API key rotation enforces configured TTL and immediately revokes predecessor',async()=>{
 let now=1_800_000_000_000;const a=await createAuth(cfg({clock:()=>now,policy:{apiKeyTtlMs:60000,maxApiKeyTtlMs:120000,apiKeyRotationTtlMs:90000}})),u=await createUser(a);await rejects(()=>a.createApiKey({subjectId:u.id,name:'too long',expiresAt:now+120001}),'INVALID_INPUT');const k=await a.createApiKey({subjectId:u.id,name:'first'});assert.equal(k.record.expiresAt,now+60000);now+=1000;const r=await a.rotateApiKey(k.record.id);assert.equal(r.record.expiresAt,now+90000);await rejects(()=>a.authenticate(key(k)),'UNAUTHENTICATED');await a.authenticate(key(r));now+=90000;await rejects(()=>a.authenticate(key(r)),'UNAUTHENTICATED');assert((await a.cleanup())>0);await a.close();
});
test('durable audit sequence, redaction, transaction rollback and cursor delivery',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a,'audit@example.test',{sensitive:'personal-info'});const k=await a.createApiKey({subjectId:u.id,name:'secret-name'});await a.revokeApiKey(k.record.id);const rows=await a.listAudit({limit:100});assert(rows.length>=4);assert.deepEqual(rows.map(x=>x.id),rows.map(x=>x.id).sort());const serialized=JSON.stringify(rows);for(const forbidden of [password,k.apiKey,'personal-info','secret-name','audit@example.test','digest','"hash"'])assert(!serialized.includes(forbidden),forbidden);const count=rows.length;await rejects(()=>a.createUser({email:u.email,password}),'CONFLICT');assert.equal((await a.listAudit()).length,count);
 const delivered=[];const batch=await a.deliverAudit({limit:2,deliver:async e=>delivered.push(e.id)});assert.equal(batch.delivered,2);await a.deliverAudit({after:batch.after,deliver:async e=>delivered.push(e.id)});assert.deepEqual(delivered,rows.map(x=>x.id));await a.close();
});
class Bytes{files=new Map();async open(n,o={}){if(o.exclusive&&this.files.has(n))throw Error('exists');if(!this.files.has(n)){if(!o.create)throw Error('missing');this.files.set(n,new Uint8Array());}return {size:async()=>this.files.get(n).length,readExactly:async(o,l)=>this.files.get(n).slice(o,o+l),write:async(o,d)=>{assert.equal(o,0);this.files.set(n,d.slice());},flush:async()=>{},close:async()=>{}};}async list(){return [...this.files.keys()];}async remove(n){return this.files.delete(n);}}
test('master key rewrap is immutable, restartable and independently cleaned',async()=>{
 const provider=new MemoryProvider(),storage=new Bytes(),old=crypto.getRandomValues(new Uint8Array(32)),next=crypto.getRandomValues(new Uint8Array(32));const common=cfg({provider});let a=await createAuth({...common,keyStore:new StorageKeyStore({storage,keyRing:{activeVersion:'v1',keys:{v1:old}}})});const u=await createUser(a),t=await login(a,u);await a.close();
 a=await createAuth({...common,keyStore:new StorageKeyStore({storage,keyRing:{activeVersion:'v2',keys:{v1:old,v2:next}}})});const k=await a.rewrapSigningKey();assert.equal(storage.files.size,2);assert((await a.jwks()).keys.some(x=>x.kid===k.kid));await a.authenticate(bearer(t));assert.equal(await a.reconcileKeyFiles({exclusive:true}),1);await a.close();
 a=await createAuth({...common,keyStore:new StorageKeyStore({storage,keyRing:{activeVersion:'v2',keys:{v2:next}}})});await a.authenticate(bearer(t));await login(a,u);await a.close();
});
test('admin service creation is authorized for the tenant it is created in',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a);await a.createTenant({id:'tenant-x'});await a.setClaims(u.id,'tenant-x',['tenant-admin']);const t=await login(a,u,'tenant-x');
 const seen=[];const h=handler(a,{authorizeAdmin:(p,op)=>{seen.push(op.tenantId);return op.tenantId==='tenant-x'&&p.tenantId==='tenant-x'&&p.hasClaim('tenant-admin');}});
 const post=(query,body)=>h.fetch(new Request('https://auth.example.test/auth/admin/services'+query,{method:'POST',headers:{authorization:bearer(t),'content-type':'application/json'},body:JSON.stringify(body)}));
 const r=await post('?tenantId=tenant-x',{name:'worker',claims:['root']});
 assert.equal(r.status,201);assert.equal((await r.json()).tenantId,'tenant-x');assert.equal((await a.listServiceAccounts('default')).length,0);
 assert.equal((await post('',{name:'worker',tenantId:'default',claims:['root']})).status,403);
 assert.equal((await a.listServiceAccounts('default')).length,0);assert.deepEqual(seen,['tenant-x','default']);await a.close();
});
test('HTTP mutations without payload accept the empty body stream Node adapters attach',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a),h=handler(a);const empty=()=>new ReadableStream({start(c){c.close();}});
 const del=t=>h.fetch(new Request('https://auth.example.test/auth/sessions/'+t.sessionId,{method:'DELETE',headers:{authorization:bearer(t)},body:empty(),duplex:'half'}));
 assert.equal((await del(await login(a,u))).status,204);
 const t=await login(a,u),bytes=new Request('https://auth.example.test/auth/sessions/'+t.sessionId,{method:'DELETE',headers:{authorization:bearer(t)},body:'{}',duplex:'half'});bytes.headers.delete('content-type');
 assert.equal((await h.fetch(bytes)).status,400);
 await a.close();
});
// defuss-storage 0.4.1 FileStorage/OPFS name contract; base64url thumbprints are mixed-case and were rejected.
const portableName=n=>/^[a-z0-9][a-z0-9._-]{0,127}$/.test(n)&&!n.endsWith('.')&&!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/.test(n);
test('encrypted key files use portable lowercase storage names across rewrap and reconcile',async()=>{
 const storage=new Bytes(),master=crypto.getRandomValues(new Uint8Array(32)),provider=new MemoryProvider();let a=await createAuth(cfg({provider,keyStore:new StorageKeyStore({storage,encryptionKey:master})}));const u=await createUser(a),t=await login(a,u);await a.rewrapSigningKey();
 assert.equal(storage.files.size,2);for(const n of storage.files.keys())assert(portableName(n),n);
 assert.equal(await a.reconcileKeyFiles({exclusive:true}),1);await a.close();
 a=await createAuth(cfg({provider,keyStore:new StorageKeyStore({storage,encryptionKey:master})}));await a.authenticate(bearer(t));await a.close();
});
test('scheduled signing rotation and retirement cleanup preserve existing tokens',async()=>{
 let now=1_800_000_000_000;const a=await createAuth(cfg({clock:()=>now,policy:{signingKeyMaxAgeMs:60000}})),u=await createUser(a),t=await login(a,u);const kid=(await a.jwks()).keys[0].kid;assert.equal((await a.maintain()).rotated,false);now+=60000;assert.equal((await a.maintain()).rotated,true);await a.authenticate(bearer(t));assert.equal((await a.jwks()).keys.length,2);await a.revokeSigningKey(kid);await rejects(()=>a.authenticate(bearer(t)),'UNAUTHENTICATED');await a.cleanup();assert.equal((await a.jwks()).keys.length,1);await a.close();
});
test('schema/configuration migration is atomic and fences stale authority instances',async()=>{
 const common=cfg(),a=await createAuth(common),u=await createUser(a,'migration@example.test',{name:'Alice'}),fingerprint=await a.configurationFingerprint();const schemas={user:{type:'object',properties:{displayName:{type:'string'}},required:['displayName'],additionalProperties:false}};
 await rejects(()=>createAuth({...common,schemas}),'UNAVAILABLE');await rejects(()=>createAuth({...common,schemas,migrateFrom:fingerprint}),'SCHEMA');assert.equal((await a.getUser(u.id)).data.name,'Alice');
 const b=await createAuth({...common,schemas,migrateFrom:fingerprint,migrateData:(kind,d)=>kind==='user'?{displayName:d.name}:d});assert.deepEqual((await b.getUser(u.id)).data,{displayName:'Alice'});await rejects(()=>a.getUser(u.id),'UNAVAILABLE');await assert.rejects(()=>b.updateUser(u.id,{data:{displayName:5}}),e=>e instanceof SchemaValidationError&&e.issues.some(x=>x.path==='/displayName'));await a.close();await b.close();
});
test('seeded authorization state machine: no stale grants or revoked keys regain access',async()=>{
 const a=await createAuth(cfg()),u=await createUser(a);await a.setClaims(u.id,'default',['read']);const keys=[];let seed=1321;const rng=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};let granted=true,incarnation=0;let claims=['read'];
 for(let i=0;i<80;i++){const op=rng()%6;if(op===0&&granted){const k=await a.createApiKey({subjectId:u.id,name:'model',claims:[...claims]});keys.push({k,incarnation,revoked:false,claims:[...claims]});}else if(op===1&&keys.length){const k=keys[rng()%keys.length];await a.revokeApiKey(k.k.record.id);k.revoked=true;}else if(op===2){await a.revokeTenantAccess(u.id,'default');granted=false;incarnation++;}else if(op===3){claims=['read'];await a.setClaims(u.id,'default',claims);granted=true;}else if(op===4&&granted){claims=[];await a.setClaims(u.id,'default',claims);}else if(op===5&&granted){claims=['read','write'];await a.setClaims(u.id,'default',claims);}
 for(const k of keys){if(!granted||k.revoked||k.incarnation!==incarnation)await rejects(()=>a.authenticate(key(k.k)),'UNAUTHENTICATED');else assert.deepEqual((await a.authenticate(key(k.k))).claims,claims.filter(c=>k.claims.includes(c)));}}
 await a.close();
});
test('seeded malformed JWT corpus always rejects at the parser boundary',()=>{let seed=47;for(let i=0;i<2000;i++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;const payload=seed.toString(36);assert.throws(()=>prepareJwt('!'+payload+'.'+payload+'.'+payload),e=>e instanceof AuthError);}});

test('HTTP client email registration, passwordless login, step-up and invitations',async()=>{
 const deliveries=[],a=await createAuth(cfg({delivery:async e=>deliveries.push(e),passwordless:true,registration:()=>true}));const h=handler(a,{authorizeAdmin:p=>p.hasClaim('admin')});const c=createAuthClient({baseUrl:'https://auth.example.test/auth',mode:'token',fetch:(u,i)=>h.fetch(new Request(u,i))});
 await c.requestRegistration({email:'client@example.test',data:{name:'client'}});await c.confirmRegistration({token:deliveries.at(-1).token,password});const u=await a.getUserByEmail('client@example.test');await a.setClaims(u.id,'default',['admin']);
 await c.requestPasswordlessLogin({email:u.email});await c.confirmPasswordlessLogin(deliveries.at(-1).token);assert.equal((await c.me()).subjectId,u.id);
 await assert.rejects(()=>c.admin.createTenant({id:'client-team'}),e=>e.status===403);await c.stepUp(password);await c.admin.createTenant({id:'client-team'});
 await c.admin.inviteToTenant({email:'invitee@example.test',tenantId:'client-team',claims:['read']});await c.acceptInvitation({token:deliveries.at(-1).token,password});const v=await a.getUserByEmail('invitee@example.test');assert.deepEqual(await a.getClaims(v.id,'client-team'),['read']);
 const i=await c.admin.inviteToTenant({email:'cancelled@example.test',tenantId:'client-team'});await c.admin.revokeInvitation(i.id);await assert.rejects(()=>c.acceptInvitation({token:deliveries.at(-1).token,password}),e=>e.status===401);await a.close();
});
test('password hash upgrade happens only after successful password proof',async()=>{
 const provider=new MemoryProvider(),base=cfg({provider}),a=await createAuth(base),u=await createUser(a);await a.close();
 const replacement={hash:async p=>'v2:'+await tag('test-only',p),verify:async(p,h)=>verifyTag('test-only',p,h.slice(h.indexOf(':')+1)),needsRehash:h=>h.startsWith('test:')};
 const b=await createAuth({...base,passwordHasher:replacement});await rejects(()=>b.login({email:u.email,password:'incorrect'}),'UNAUTHENTICATED');assert((await provider.read(r=>r.get('credentials',u.id))).hash.startsWith('test:'));await login(b,u);assert((await provider.read(r=>r.get('credentials',u.id))).hash.startsWith('v2:'));await login(b,u);await b.close();
});
test('authority configuration captured at initialization and email flows require delivery',async()=>{
 await rejects(()=>createAuth(cfg({passwordless:true})),'INVALID_INPUT');const config=cfg(),a=await createAuth(config);config.passwordless=true;config.delivery=async()=>{};await rejects(()=>a.requestPasswordlessLogin({email:'any@example.test'}),'FORBIDDEN');await a.close();
});
test('global public admission bound limits unknown accounts and persists across instances',async()=>{
 const common=cfg({policy:{globalRateAttempts:3}}),a=await createAuth(common);for(let i=0;i<3;i++)await rejects(()=>a.login({email:`unknown${i}@example.test`,password}),'UNAUTHENTICATED');await a.close();const b=await createAuth(common);await rejects(()=>b.login({email:'different@example.test',password}),'RATE_LIMIT');const rows=await common.provider.read(r=>r.list('rates'));assert(rows.length<=4);await b.close();
});
