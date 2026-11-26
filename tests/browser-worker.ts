import {createAuth} from 'defuss-auth/browser';
const scope=globalThis as unknown as {postMessage(value:unknown):void};
(async()=>{
 const cfg={issuer:'https://browser.example.test',audience:'local-only',insecureLocalAuthority:true as const,encryptionKey:crypto.getRandomValues(new Uint8Array(32)),namespace:'test-'+crypto.randomUUID()};
 let auth=await createAuth(cfg);
 const u=await auth.createUser({email:'local@example.test',password:'browser long password'});
 await auth.grantClaim(u.id,'default','read');
 const t=await auth.login({email:u.email,password:'browser long password'});
 await auth.close();auth=await createAuth(cfg);
 if(!(await auth.authenticate('Bearer '+t.accessToken)).hasClaim('read'))throw Error('Claim missing');
 const k=await auth.createApiKey({userId:u.id,name:'local',claims:['read']});
 if(!(await auth.authenticate('ApiKey '+k.apiKey)).hasClaim('read'))throw Error('API key missing');
 await auth.revokeApiKey(k.record.id);let rejected=false;try{await auth.authenticate('ApiKey '+k.apiKey);}catch{rejected=true;}if(!rejected)throw Error('Revoked key accepted');
 const service=await auth.createServiceAccount({name:'worker',claims:['read']});const serviceKey=await auth.createApiKey({subjectId:service.id,name:'worker'});if((await auth.authenticate('ApiKey '+serviceKey.apiKey)).subjectKind!=='service')throw Error('service subject');
 await auth.close();scope.postMessage({passed:true});
})().catch(error=>scope.postMessage({passed:false,error:String(error)}));
