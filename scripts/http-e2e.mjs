/** Every HTTP route once, over real loopback HTTP, the built package, real defuss-db/storage and native Argon2id. */
import assert from 'node:assert/strict';
import {mkdtemp,realpath,rm,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createAuth} from 'defuss-auth/server';
import {createAuthHandler} from 'defuss-auth/serve';
import {createAuthClient} from 'defuss-auth/client';
import {listen} from './http-bridge.mjs';
const id='[A-Za-z0-9_-]+';
// Mirrors the route table in src/serve.ts; a route missing here or never answered with 2xx fails the gate.
// VERIFIED: this run found the empty-body DELETE defect that in-process Fetch tests missed.
const routes=[['GET','/.well-known/jwks.json'],['POST','/auth/login'],['POST','/auth/login/email/request'],['POST','/auth/login/email/confirm'],['POST','/auth/register/request'],['POST','/auth/register/confirm'],['POST','/auth/invitation/accept'],['POST','/auth/password/step-up'],['POST','/auth/refresh'],['POST','/auth/logout'],['POST','/auth/logout-all'],['POST','/auth/token/revoke'],['GET','/auth/me'],['GET','/auth/sessions'],['DELETE',`/auth/sessions/${id}`],['GET','/auth/tenants'],['POST','/auth/tenant/switch'],['POST','/auth/password/change'],['POST','/auth/password/reset/request'],['POST','/auth/password/reset/confirm'],['POST','/auth/email/verify/request'],['POST','/auth/email/verify/confirm'],['GET','/auth/api-keys'],['POST','/auth/api-keys'],['GET',`/auth/api-keys/${id}`],['PATCH',`/auth/api-keys/${id}`],['DELETE',`/auth/api-keys/${id}`],['POST',`/auth/api-keys/${id}/rotate`],
 ['POST','/auth/admin/invitations'],['DELETE',`/auth/admin/invitations/${id}`],['GET',`/auth/admin/services/${id}/api-keys`],['POST',`/auth/admin/services/${id}/api-keys`],['GET',`/auth/admin/services/${id}/api-keys/${id}`],['PATCH',`/auth/admin/services/${id}/api-keys/${id}`],['DELETE',`/auth/admin/services/${id}/api-keys/${id}`],['POST',`/auth/admin/services/${id}/api-keys/${id}/rotate`],
 ...['users','tenants','services'].flatMap(r=>[['GET',`/auth/admin/${r}`],['POST',`/auth/admin/${r}`],['GET',`/auth/admin/${r}/${id}`],['PATCH',`/auth/admin/${r}/${id}`],['DELETE',`/auth/admin/${r}/${id}`]]),
 ...['users','services'].flatMap(r=>[['GET',`/auth/admin/${r}/${id}/claims`],['GET',`/auth/admin/${r}/${id}/claims/${id}`],['PUT',`/auth/admin/${r}/${id}/claims/${id}`],['DELETE',`/auth/admin/${r}/${id}/claims/${id}`]])
].map(([method,path])=>({method,path,re:new RegExp('^'+path+'$'),ok:false}));
const dir=await realpath(await mkdtemp(join(tmpdir(),'defuss-auth-http-')));
const mail=[];const token=(kind,email)=>{const m=mail.findLast(x=>x.kind===kind&&x.email===email);assert(m,kind+' '+email);return m.token;};
const pw='http e2e long password',pw2='http e2e replacement password';
let auth,server;
try{
 auth=await createAuth({issuer:'https://http-e2e.example.test',audience:'http-e2e',storage:{directory:dir},encryptionKey:crypto.getRandomValues(new Uint8Array(32)),passwordless:true,registration:()=>true,delivery:async e=>{mail.push(e);}});
 const handler=createAuthHandler(auth,{mode:'token',authorizeAdmin:p=>p.hasClaim('root')});
 server=await listen(async req=>{const res=await handler.fetch(req);const path=new URL(req.url).pathname;for(const r of routes)if(r.method===req.method&&r.re.test(path)&&res.status<400)r.ok=true;return res;});
 const client=()=>createAuthClient({baseUrl:server.url+'/auth',mode:'token'});
 const root=await auth.createUser({email:'root@example.test',password:pw});await auth.grantClaim(root.id,'default','root');
 assert((await (await fetch(server.url+'/.well-known/jwks.json')).json()).keys.length>=1);
 const a=client();await a.login({email:root.email,password:pw});
 assert.equal((await a.me()).subjectId,root.id);assert.deepEqual(await a.listTenants(),['default']);assert.equal((await a.listSessions()).length,1);
 // Tenants, users and grants.
 await a.admin.createTenant({id:'acme'});assert((await a.admin.listTenants()).some(t=>t.id==='acme'));assert.equal((await a.admin.getTenant('acme')).id,'acme');await a.admin.updateTenant('acme',{data:{name:'Acme'}});
 const bob=await a.admin.createUser({email:'bob@example.test',password:pw});assert((await a.admin.listUsers()).some(u=>u.id===bob.id));assert.equal((await a.admin.getUser(bob.id)).email,bob.email);await a.admin.updateUser(bob.id,{data:{n:1}});
 assert.deepEqual(await a.admin.setClaims(bob.id,'acme',['read']),['read']);assert.deepEqual(await a.admin.getClaims(bob.id,'acme'),['read']);assert((await a.admin.listTenantIds(bob.id)).includes('acme'));await a.admin.revokeTenantAccess(bob.id,'acme');
 // Service accounts, their grants and API keys.
 const svc=await a.admin.createServiceAccount({tenantId:'acme',name:'worker',claims:['read']});assert.equal(svc.tenantId,'acme');assert((await a.admin.listServiceAccounts('acme')).some(s=>s.id===svc.id));assert.equal((await a.admin.getServiceAccount(svc.id)).id,svc.id);await a.admin.updateServiceAccount(svc.id,{name:'worker-2'});
 assert.deepEqual(await a.admin.setServiceClaims(svc.id,'acme',['read','write']),['read','write']);assert.deepEqual(await a.admin.getServiceClaims(svc.id,'acme'),['read','write']);assert.deepEqual(await a.admin.listServiceTenantIds(svc.id),['acme']);
 const sk=await a.admin.createServiceApiKey(svc.id,{name:'k',claims:['read']});assert.equal((await auth.authenticate('ApiKey '+sk.apiKey)).subjectKind,'service');assert.equal((await a.admin.listServiceApiKeys(svc.id)).length,1);assert.equal((await a.admin.getServiceApiKey(svc.id,sk.record.id)).id,sk.record.id);await a.admin.updateServiceApiKey(svc.id,sk.record.id,{name:'k2'});
 const sk2=await a.admin.rotateServiceApiKey(svc.id,sk.record.id);await assert.rejects(()=>auth.authenticate('ApiKey '+sk.apiKey));await a.admin.revokeServiceApiKey(svc.id,sk2.record.id);await assert.rejects(()=>auth.authenticate('ApiKey '+sk2.apiKey));
 const svc2=await a.admin.createServiceAccount({tenantId:'acme',name:'temp'});await a.admin.revokeServiceTenantAccess(svc2.id,'acme');await a.admin.deleteServiceAccount(svc.id);assert.equal(await auth.getServiceAccount(svc.id),undefined);
 // Invitations.
 const spare=await a.admin.inviteToTenant({email:'spare@example.test',tenantId:'acme'});await a.admin.revokeInvitation(spare.id);
 await a.admin.inviteToTenant({email:'carol@example.test',tenantId:'acme',claims:['read']});
 const c=client();await c.acceptInvitation({token:token('invite','carol@example.test'),password:pw});await c.login({email:'carol@example.test',password:pw,tenantId:'acme'});
 // Sessions: revoke one by id, log out another, log out a tenant.
 const other=client();await other.login({email:'carol@example.test',password:pw,tenantId:'acme'});const mine=(await c.me()).sessionId;const foreign=(await c.listSessions()).find(s=>s.id!==mine&&s.revokedAt===null);await c.revokeSession(foreign.id);
 const leaving=client();await leaving.login({email:'carol@example.test',password:pw,tenantId:'acme'});await leaving.logout();
 const all=client();await all.login({email:'carol@example.test',password:pw,tenantId:'acme'});await all.logoutAll('tenant');await assert.rejects(()=>c.me());
 await c.login({email:'carol@example.test',password:pw,tenantId:'acme'});assert.equal(await c.refresh(),true);await c.stepUp(pw);
 // Personal API keys.
 const k=await c.createApiKey({name:'mine',claims:['read']});assert.equal((await c.listApiKeys()).length,1);assert.equal((await c.getApiKey(k.record.id)).name,'mine');await c.updateApiKey(k.record.id,{name:'renamed'});const k2=await c.rotateApiKey(k.record.id);await c.revokeApiKey(k2.record.id);await assert.rejects(()=>auth.authenticate('ApiKey '+k2.apiKey));
 const spareToken=await auth.login({email:'carol@example.test',password:pw,tenantId:'acme'});await c.revokeToken(spareToken.accessToken);await assert.rejects(()=>auth.authenticate('Bearer '+spareToken.accessToken));
 await c.changePassword(pw,pw2);assert.equal(c.state().authenticated,false);await c.login({email:'carol@example.test',password:pw2,tenantId:'acme'});
 // Email challenges: verification, reset, passwordless login and registration.
 await a.requestEmailVerification({email:bob.email});await a.verifyEmail(token('verify',bob.email));assert.equal((await auth.getUser(bob.id)).emailVerified,true);
 await a.requestPasswordReset({email:bob.email});await a.resetPassword({token:token('reset',bob.email),newPassword:pw2});
 const b=client();await b.requestPasswordlessLogin({email:bob.email});await b.confirmPasswordlessLogin(token('login',bob.email));assert.equal((await b.me()).subjectId,bob.id);
 await b.requestRegistration({email:'dave@example.test'});await b.confirmRegistration({token:token('register','dave@example.test'),password:pw});assert(await auth.getUserByEmail('dave@example.test'));
 // Tenant switch last: the admin loses its root claim outside the default tenant.
 await a.admin.setClaims(root.id,'acme',[]);await a.switchTenant('acme');assert.equal((await a.me()).tenantId,'acme');
 // A grant change invalidates the access token; refresh reissues it with the new claims.
 await auth.setClaims(root.id,'acme',['root']);assert.equal(await a.refresh(),true);await a.admin.deleteUser(bob.id);await a.admin.deleteTenant('acme');
 const missing=routes.filter(r=>!r.ok).map(r=>r.method+' '+r.path);assert.deepEqual(missing,[],'routes without a 2xx answer');
 const platform=globalThis.Bun?'bun':'node';await mkdir('output',{recursive:true});await writeFile(`output/http-e2e-${platform}.json`,JSON.stringify({passed:true,runtime:process.version,routes:routes.length}));
 console.log(`HTTP ${platform}: ${routes.length} routes passed`);
}finally{await server?.close();await auth?.close();await rm(dir,{recursive:true,force:true});}
