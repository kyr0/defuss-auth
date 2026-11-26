/** Real persistent-process race and SIGKILL after durable refresh commit, never a simulated DB. */
import {createAuth} from 'defuss-auth/server';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,realpath,access,readFile,writeFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
const root=await realpath(await mkdtemp(join(tmpdir(),'defuss-auth-concurrency-'))),directory=join(root,'authority'),master=crypto.getRandomValues(new Uint8Array(32));
const cfg={issuer:'https://multiprocess.example.test',audience:'native-concurrency',storage:{directory},encryptionKey:master},pw='integration fixture password';
let auth;const children=new Set();
async function waitFor(path,ms=30000){const until=Date.now()+ms;while(Date.now()<until){try{await access(path);return;}catch(e){if(e.code!=='ENOENT')throw e;}await new Promise(r=>setTimeout(r,20));}throw Error('Timed out: '+path);}
function worker(name,refreshToken,go,crash=false){const ready=join(root,name+'.ready'),result=join(root,name+'.result');const child=spawn(process.execPath,[resolve('scripts/native-worker.mjs')],{env:{...process.env,DEFUSS_AUTH_NATIVE_FIXTURE:JSON.stringify({directory,master:[...master],refreshToken,ready,result,go,crash})},stdio:['ignore','ignore','inherit']});children.add(child);const done=new Promise((res,rej)=>{child.on('error',rej);child.on('exit',(code,signal)=>{children.delete(child);res({code,signal});});});return {ready,result,done};}
try{
 auth=await createAuth(cfg);const u=await auth.createUser({email:'fixture@example.test',password:pw});const first=await auth.login({email:u.email,password:pw});await auth.close();auth=undefined;
 const go=join(root,'race.go'),a=worker('a',first.refreshToken,go),b=worker('b',first.refreshToken,go);
 await Promise.all([waitFor(a.ready),waitFor(b.ready)]);await writeFile(go,'go');const outcomes=await Promise.all([a.done,b.done]);assert(outcomes.every(x=>x.code===0));const r=await Promise.all([a,b].map(async x=>JSON.parse(await readFile(x.result,'utf8'))));assert.equal(r.filter(x=>x.accessToken).length,1);assert.equal(r.filter(x=>x.error==='UNAUTHENTICATED').length,1);
 auth=await createAuth(cfg);await assert.rejects(()=>auth.authenticate('Bearer '+r.find(x=>x.accessToken).accessToken));const second=await auth.login({email:u.email,password:pw});await auth.close();auth=undefined;
 const crashGo=join(root,'crash.go'),c=worker('crash',second.refreshToken,crashGo,true);await waitFor(c.ready);await writeFile(crashGo,'go');await waitFor(c.result);assert.equal((await c.done).signal,'SIGKILL');
 auth=await createAuth(cfg);await assert.rejects(()=>auth.refresh(second.refreshToken),e=>e.code==='UNAUTHENTICATED');await assert.rejects(()=>auth.authenticate('Bearer '+second.accessToken));await auth.close();auth=undefined;
 await mkdir('output',{recursive:true});await writeFile('output/native-concurrency-'+(globalThis.Bun?'bun':'node')+'.json',JSON.stringify({passed:true,runtime:process.version,race:true,postCommitSigkill:true}));
}finally{for(const c of children)c.kill('SIGKILL');await auth?.close();await rm(root,{recursive:true,force:true});}
