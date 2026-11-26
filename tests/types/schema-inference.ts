import {createAuth, type AuthOptions} from '../../src/index.js';
import {createAuthClient} from '../../src/client.js';
const schemas={user:{type:'object',properties:{displayName:{type:'string'},rank:{type:'integer'}},required:['displayName']},service:{type:'object',properties:{purpose:{enum:['index','query']}},required:['purpose']}} as const;
export async function check(config:AuthOptions){
 const auth=await createAuth({...config,schemas});
 const user=await auth.createUser({email:'user@example.test',data:{displayName:'Alice'}});
 const name:string=user.data.displayName;
 const rank:number|undefined=user.data.rank;
 // @ts-expect-error rank must be a number
 await auth.updateUser(user.id,{data:{displayName:name,rank:'high'}});
 // @ts-expect-error required displayName must be present
 await auth.createUser({email:'user@example.test',data:{rank:3}});
 const principal=await auth.requireAuth('Bearer token');
 const n:string|undefined=(await principal.getUser())?.data.displayName;
 const client=createAuthClient({baseUrl:'https://example.test/auth',schemas});
 const service=await client.admin.createServiceAccount({name:'worker',data:{purpose:'query'}});
 const purpose:'index'|'query'=service.data.purpose;
 // @ts-expect-error unsupported service type
 await client.admin.createServiceAccount({name:'worker',data:{purpose:'wrong'}});
 // @ts-expect-error typed registration data
 await client.requestRegistration({email:'a@example.test',data:{displayName:5}});
 return {name,rank,n,purpose};
}
