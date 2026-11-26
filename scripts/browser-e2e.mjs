import {chromium,firefox,webkit} from 'playwright';
import {build} from 'esbuild';
import {listen} from './http-bridge.mjs';
import {mkdir,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
const bundled=await build({entryPoints:['tests/browser-worker.ts'],bundle:true,write:false,platform:'browser',format:'esm',target:'es2022'});
const code=bundled.outputFiles[0].text;
const server=await listen(req=>new URL(req.url).pathname==='/worker.js'?new Response(code,{headers:{'content-type':'application/javascript'}}):new Response('<!doctype html><title>OPFS test</title>',{headers:{'content-type':'text/html'}}));
// Persistent profiles. VERIFIED: (probe 2026-11-24) an ephemeral WebKit context is private browsing, where navigator.storage.getDirectory() rejects.
const results=[];try{for(const [name,engine] of Object.entries({chromium,firefox,webkit})){const profile=await mkdtemp(join(tmpdir(),'defuss-auth-'+name+'-'));const context=await engine.launchPersistentContext(profile,{headless:true});try{const page=context.pages()[0]??await context.newPage();await page.goto(server.url);const r=await page.evaluate(()=>new Promise((resolve,reject)=>{const worker=new Worker('/worker.js',{type:'module'});const timer=setTimeout(()=>{worker.terminate();reject(Error('Worker timed out'));},60000);worker.onmessage=e=>{clearTimeout(timer);worker.terminate();resolve(e.data);};worker.onerror=e=>{clearTimeout(timer);reject(Error(e.message));};}));assert.equal(r.passed,true,name+': '+JSON.stringify(r));results.push({browser:name,version:context.browser()?.version()??engine.name(),passed:true});}finally{await context.close();await rm(profile,{recursive:true,force:true});}}await mkdir('output',{recursive:true});await writeFile('output/browser-e2e.json',JSON.stringify(results,null,2));}finally{await server.close();}
