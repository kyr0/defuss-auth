/** Synthetic fixture worker for real multiprocess and forced termination integration tests. */
import {createAuth} from 'defuss-auth/server';
import {writeFile} from 'node:fs/promises';
const input=JSON.parse(process.env.DEFUSS_AUTH_NATIVE_FIXTURE);
const a=await createAuth({issuer:'https://multiprocess.example.test',audience:'native-concurrency',storage:{directory:input.directory},encryptionKey:new Uint8Array(input.master)});
try{
 await writeFile(input.ready,'ready',{flag:'wx'});
 const {access}=await import('node:fs/promises');
 for(;;){try{await access(input.go);break;}catch(e){if(e.code!=='ENOENT')throw e;await new Promise(r=>setTimeout(r,10));}}
 const t=await a.refresh(input.refreshToken);
 if(input.crash){await writeFile(input.result,JSON.stringify({committed:true}),{flag:'wx'});process.kill(process.pid,'SIGKILL');await new Promise(()=>{});}
 await writeFile(input.result,JSON.stringify({accessToken:t.accessToken}),{flag:'wx'});
}catch(e){await writeFile(input.result,JSON.stringify({error:e.code??'UNAVAILABLE'}),{flag:'wx'});}
finally{await a.close();}
