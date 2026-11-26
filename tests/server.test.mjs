import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,mkdir,mkdtemp,realpath,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createAuth} from '../build/test/server.js';
import {AuthError} from '../build/test/index.js';
// These refusals happen before defuss-db or defuss-storage load, so the test needs neither peer.
const cfg=directory=>({issuer:'https://native.example.test',audience:'native',encryptionKey:new Uint8Array(32),storage:{directory}});
const refused=(directory,pattern)=>assert.rejects(()=>createAuth(cfg(directory)),e=>e instanceof AuthError&&e.code==='UNAVAILABLE'&&pattern.test(e.message));

test('native storage refuses symlinked, non-canonical and shared directories', {skip:process.platform==='win32'}, async t=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'defuss-auth-dir-')));t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'target'),{mode:0o700});await symlink(join(root,'target'),join(root,'link'));
 await refused(join(root,'link'),/canonical path; pass its realpath/);                 // the directory itself is a link
 await refused(join(root,'link','auth'),/canonical path; pass its realpath/);          // an ancestor is a link
 await mkdir(join(root,'shared'),{mode:0o700});await chmod(join(root,'shared'),0o755);
 await refused(join(root,'shared'),/owner-only \(0700\)/);
 const keys=join(root,'keys-shared');await mkdir(join(keys,'keys'),{recursive:true,mode:0o700});await chmod(join(keys,'keys'),0o750);
 await refused(keys,/owner-only \(0700\)/);                                             // the keys subdirectory too
});

test('native storage requires a 256-bit master key unless a key store is supplied', async()=>{
 const saved=process.env.DEFUSS_AUTH_MASTER_KEY;delete process.env.DEFUSS_AUTH_MASTER_KEY;
 try{
  for(const encryptionKey of [undefined,new Uint8Array(16)])
   await assert.rejects(()=>createAuth({issuer:'https://native.example.test',audience:'native',encryptionKey,storage:{directory:'/nonexistent'}}),e=>e instanceof AuthError&&e.code==='INVALID_INPUT');
 }finally{if(saved!==undefined)process.env.DEFUSS_AUTH_MASTER_KEY=saved;}
});
