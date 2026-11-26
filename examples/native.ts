import {createAuth} from 'defuss-auth/server';
import {authPlugin} from 'defuss-auth/serve';

// Master key is read from DEFUSS_AUTH_MASTER_KEY, or set encryptionKey explicitly.
const auth = await createAuth({
  issuer: 'https://api.example.com',
  audience: 'example-app',
  storage: {directory:'./data/auth'},
  schemas: {user:{type:'object',properties:{displayName:{type:'string'}},required:['displayName'],additionalProperties:false}}
});
const plugin = authPlugin(auth,{allowedOrigins:['https://app.example.com'],ownAuth:true});
// Pass plugin to defuss-serve; reserve the namespace before static files.
export {auth,plugin};
