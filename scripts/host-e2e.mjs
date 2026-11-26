/** The hosted deployment end to end: an app server proxies /auth to a backplane-style server that mounts the built
 * defuss-auth/host plugin, both on real defuss-serve listeners, with real defuss-db, defuss-storage and Argon2id.
 * Browsers (Node only) log in through the proxy in cookie mode (Chromium, Firefox) and token mode (WebKit). */
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,realpath,rename,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'defuss-serve';
import {proxyPlugin as proxy} from 'defuss-serve/plugins';
import {createAuthHost,tenantAdmin} from 'defuss-auth/host';
import {createAuthClient} from 'defuss-auth/client';
const platform=globalThis.Bun?'bun':'node',KEY='e2e-backplane-key-0123456789abcdef',pw='host e2e long password';
const root=await realpath(await mkdtemp(join(tmpdir(),'defuss-auth-host-'))),dir=join(root,'auth'),pub=join(root,'public');
const masterKey=crypto.getRandomValues(new Uint8Array(32));
let host,bp,app;const out={platform,runtime:globalThis.Bun?'bun '+Bun.version:'node '+process.version,proxy:'defuss-serve proxyPlugin'};
const openApps=async(h,origin)=>{await h.open('linear-clone',{issuer:'https://linear-clone.apps.test',audience:'linear-clone',http:{mode:'cookie',allowedOrigins:[origin],authorizeAdmin:tenantAdmin('admin')}});
 // A browser sends Origin on every write, so token mode from a page needs the origin listed too.
 await h.open('other',{issuer:'https://other.apps.test',audience:'other',http:{mode:'token',allowedOrigins:[origin]}});
 // A tight limit, so the rate check below needs few Argon2id verifications.
 await h.open('limited',{issuer:'https://limited.apps.test',audience:'limited',policy:{rateAttempts:1},http:{mode:'token'}});};
try{
 host=await createAuthHost({directory:dir,masterKey,credential:{header:'x-backplane-key',secret:KEY}});
 // The backplane trusts its loopback app proxies, so their X-Forwarded-For survives to the rate keys.
 bp=createServer({host:'127.0.0.1',port:0,trustedProxies:['127.0.0.1'],plugins:[host.plugin()]});await bp.start();
 await mkdir(pub,{recursive:true});await writeFile(join(pub,'client.mjs'),await readFile(new URL('../dist/client.mjs',import.meta.url)));
 await writeFile(join(pub,'index.html'),`<!doctype html><meta charset="utf-8"><title>host e2e</title><script type="module">import {createAuthClient} from '/client.mjs';
 const mode=new URLSearchParams(location.search).get('mode')??'cookie',c=createAuthClient({baseUrl:location.origin+(mode==='cookie'?'/auth':'/tauth'),mode});
 window.probe={login:async(email,password,tenantId)=>{await c.login({email,password,tenantId});return c.state().authenticated;},refresh:()=>c.refresh().catch(e=>'error:'+e.code),
 who:async()=>{const r=await c.fetch('/api/whoami?app='+(mode==='cookie'?'linear-clone':'other'));return [r.status,await r.json()];},logout:async()=>{await c.logout();return c.state().authenticated;}};window.ready=true;</script>`);
 const whoami={name:'whoami',routes:[{path:'/api/whoami',methods:['GET']}],async fetch(req){
  // In the backplane this is one RPC call; here the app calls the host in-process.
  try{return Response.json(await host.authenticate(new URL(req.url).searchParams.get('app'),req.headers.get('authorization')??''));}catch(e){return Response.json({error:e.code},{status:401});}}};
 const appPlugins=()=>[proxy('/auth',bp.url.href.replace(/\/$/,'')+'/apps/linear-clone/auth',{headers:{'X-Backplane-Key':KEY}}),proxy('/tauth',bp.url.href.replace(/\/$/,'')+'/apps/other/auth',{headers:{'X-Backplane-Key':KEY}}),proxy('/lauth',bp.url.href.replace(/\/$/,'')+'/apps/limited/auth',{headers:{'X-Backplane-Key':KEY}}),whoami];
 app=createServer({host:'127.0.0.1',port:0,publicDir:pub,plugins:appPlugins()});await app.start();const origin=app.url.origin;
 await openApps(host,origin);const lc=host.get('linear-clone'),other=host.get('other');
 const ann=await lc.createUser({email:'ann@example.test',password:pw});await lc.createTenant({id:'vector'});await lc.setClaims(ann.id,'vector',['member','admin']);
 const bob=await other.createUser({email:'ann@example.test',password:pw+' other'});
 // Token mode through the proxy: login, me, refresh, API keys, logout; the app's live check of each credential.
 const t=createAuthClient({baseUrl:origin+'/tauth',mode:'token'});await t.login({email:'ann@example.test',password:pw+' other'});
 assert.equal((await t.me()).subjectId,bob.id);assert.equal(await t.refresh(),true);
 const k=await t.createApiKey({name:'agent'});assert.equal((await (await fetch(origin+'/api/whoami?app=other',{headers:{authorization:'ApiKey '+k.apiKey}})).json()).method,'apiKey');
 await t.revokeApiKey(k.record.id);assert.equal((await fetch(origin+'/api/whoami?app=other',{headers:{authorization:'ApiKey '+k.apiKey}})).status,401);
 const foreign=(await other.login({email:'ann@example.test',password:pw+' other'})).accessToken;
 assert.equal((await fetch(origin+'/api/whoami?app=linear-clone',{headers:{authorization:'Bearer '+foreign}})).status,401);
 await t.logout();assert.equal(t.state().authenticated,false);
 // The backplane refuses a caller without the proxy credential, and a cookie-mode write without Origin.
 assert.equal((await fetch(bp.url.href+'apps/linear-clone/auth/me')).status,403);
 assert.equal((await fetch(origin+'/auth/login',{method:'POST',headers:{'content-type':'application/json','x-defuss-csrf':'1'},body:JSON.stringify({email:'ann@example.test',password:pw,tenantId:'vector'})})).status,403);
 // A tenant administrator through the proxy: creates a service account in its tenant, nowhere else.
 const adm=await (await fetch(origin+'/auth/login',{method:'POST',headers:{'content-type':'application/json','x-defuss-csrf':'1',origin},body:JSON.stringify({email:'ann@example.test',password:pw,tenantId:'vector'})})).json();
 const admin=(q,body)=>fetch(origin+'/auth/admin/services'+q,{method:'POST',headers:{'content-type':'application/json','x-defuss-csrf':'1',origin,authorization:'Bearer '+adm.accessToken},body:JSON.stringify(body)});
 assert.equal((await admin('?tenantId=vector',{name:'mcp-agent',claims:['member']})).status,201);assert.equal((await admin('?tenantId=default',{name:'x'})).status,403);
 out.tokenProxy=out.isolation=out.credential=out.tenantAdmin='passed';
 if(platform==='node'){const {chromium,firefox,webkit}=await import('playwright');out.browsers=[];
  for(const [name,engine,mode] of [['chromium',chromium,'cookie'],['firefox',firefox,'cookie'],['webkit',webkit,'token']]){const browser=await engine.launch();try{const page=await (await browser.newContext()).newPage();
   const go=async()=>{await page.goto(origin+'/?mode='+mode);await page.waitForFunction(()=>window.ready);};await go();
   const [email,password,tenantId]=mode==='cookie'?['ann@example.test',pw,'vector']:['ann@example.test',pw+' other',undefined];
   assert.equal(await page.evaluate(a=>probe.login(...a),[email,password,tenantId]),true,name);
   const [st,who]=await page.evaluate(()=>probe.who());assert.equal(st,200,name);assert.equal(who.tenantId,mode==='cookie'?'vector':'default');
   if(mode==='cookie'){await go();assert.equal(await page.evaluate(()=>probe.refresh()),true,name+' refresh after reload');assert.equal((await page.evaluate(()=>probe.who()))[0],200);
    assert.deepEqual((await page.context().cookies()).map(c=>[c.name,c.path,c.httpOnly]),[['__Secure-defuss_refresh','/auth',true]]);}
   assert.equal(await page.evaluate(()=>probe.logout()),false);await go();assert.notEqual(await page.evaluate(()=>probe.refresh()),true,name+' refresh after logout');
   out.browsers.push({browser:name,version:browser.version(),mode,passed:true});}finally{await browser.close();}}}
 // The forwarded client reaches the rate keys through both listeners: five failed logins per source, then 429.
 // VERIFIED: (mutation, 2026-11-26) without trustedProxies on the service listener all six answer 401.
 // Emails in distinct per-account buckets (base64url SHA-256 prefix, as auth.ts derives them), so only the source limit can answer 429.
 const emails=[],seen=new Set();for(let i=0;emails.length<6;i++){const e='nobody'+i+'@example.test',b=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('login-account\0'+e))).toString('base64url').slice(0,2);if(!seen.has(b)){seen.add(b);emails.push(e);}}
 const statuses=[];for(const email of emails)statuses.push((await fetch(origin+'/lauth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email,password:'wrong password here'})})).status);
 assert.deepEqual(statuses,[401,401,401,401,401,429]);out.rateKey='passed';
 // Restart: the same master key reopens every app; another key, or another app name over the same files, cannot.
 await host.closeAll();host=await createAuthHost({directory:dir,masterKey,credential:{header:'x-backplane-key',secret:KEY}});await openApps(host,origin);
 assert.equal((await host.get('linear-clone').login({email:'ann@example.test',password:pw,tenantId:'vector'})).sessionId.length>0,true);await host.closeAll();
 const wrong=await createAuthHost({directory:dir,masterKey:crypto.getRandomValues(new Uint8Array(32))});
 // The refusal must come from the key files, not from a configuration mismatch.
 const keyFailure=e=>/Signing key unavailable or corrupt/.test(e?.message)||/Signing key unavailable or corrupt/.test(e?.cause?.message);
 await assert.rejects(async()=>{await wrong.open('linear-clone',{issuer:'https://linear-clone.apps.test',audience:'linear-clone'});await wrong.get('linear-clone').login({email:'ann@example.test',password:pw,tenantId:'vector'});},keyFailure);
 await wrong.closeAll().catch(()=>{});
 await rename(join(dir,'other'),join(dir,'renamed'));const moved=await createAuthHost({directory:dir,masterKey});
 await assert.rejects(async()=>{await moved.open('renamed',{issuer:'https://other.apps.test',audience:'other'});await moved.get('renamed').login({email:'ann@example.test',password:pw+' other'});},keyFailure);
 await moved.closeAll().catch(()=>{});out.keys='passed';
 await mkdir('output',{recursive:true});await writeFile(`output/host-e2e-${platform}.json`,JSON.stringify({passed:true,...out},null,1));
 console.log(`host ${platform}: passed (${out.proxy})`);
}finally{await app?.stop();await bp?.stop();await host?.closeAll().catch(()=>{});await rm(root,{recursive:true,force:true});}
