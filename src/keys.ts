import { importPrivate,jwkThumbprint,type KeyPair } from './jwt.js';
import { b64,fail,id,object,parseJson,random,text,unb64,utf8 } from './util.js';
/** The database publishes a key-file reference only after its immutable file is durable. */
export interface KeyStore {
    save(pair: KeyPair): Promise<void>;
    load(kid: string, generation?: string): Promise<JsonWebKey>;
    rewrap?(kid:string, generation?:string):Promise<string>;
    reconcile?(keep:readonly KeyReference[], limit:number):Promise<number>;
}
export interface KeyReference {kid:string; generation?:string}
export class MemoryKeyStore implements KeyStore {
    private keys = new Map<string, JsonWebKey>();
    async save(p: KeyPair) {
        if (this.keys.has(p.kid)) fail('CONFLICT');
        this.keys.set(p.kid, structuredClone(p.privateJwk));
    }
    async load(k: string) {
        const p = this.keys.get(k);
        if (!p) fail('UNAVAILABLE', 'Missing signing key');
        return structuredClone(p);
    }
    async reconcile(keep:readonly KeyReference[],limit:number){let removed=0;const ids=new Set(keep.map(k=>k.kid));for(const kid of this.keys.keys()){if(!ids.has(kid)){this.keys.delete(kid);if(++removed===limit)break;}}return removed;}
}
export interface ByteFile {
    size(): Promise<number>;
    readExactly(offset: number, length: number): Promise<Uint8Array>;
    write(offset: number, data: Uint8Array): Promise<void>;
    flush(): Promise<void>;
    close(): Promise<void>;
}
/** Names passed to a ByteStorage are flat lowercase `[a-z0-9._-]`, at most 128 characters. */
export interface ByteStorage {
    open(name: string, options?: {create?: boolean;exclusive?: boolean;readOnly?: boolean}): Promise<ByteFile>;
    list?():Promise<string[]>;
    remove?(name:string):Promise<boolean>;
}
export interface MasterKeyRing { activeVersion:string; keys:Readonly<Record<string,Uint8Array>>; }
const keyVersion=(v:string)=>{if(typeof v!=='string'||!/^[a-zA-Z0-9_-]{1,64}$/.test(v))fail('INVALID_INPUT','Invalid key version');return v;};
/** AES-GCM encrypted immutable JWK files. Supports v1 envelopes and versioned v2 keyrings. */
export class StorageKeyStore implements KeyStore {
    private readonly keys = new Map<string,Promise<CryptoKey>>();
    private readonly version:string;
    private readonly storage: ByteStorage;
    private readonly syncDirectory?: () => Promise<void>;
    constructor(o: {storage: ByteStorage; encryptionKey?: Uint8Array; keyRing?:MasterKeyRing; syncDirectory?: () => Promise<void>}) {
        if(!!o.encryptionKey===!!o.keyRing)fail('INVALID_INPUT','Supply one encryption key or keyring');
        const ring=o.keyRing??{activeVersion:'legacy',keys:{legacy:o.encryptionKey!}};
        this.version=keyVersion(ring.activeVersion);
        if(Object.keys(ring.keys).length>32)fail('INVALID_INPUT','Too many master keys');
        for(const [v,k] of Object.entries(ring.keys)){
            if(!(k instanceof Uint8Array)||k.length!==32)fail('INVALID_INPUT','Expected 256-bit master key');
            this.keys.set(keyVersion(v),crypto.subtle.importKey('raw',k.slice(),'AES-GCM',false,['encrypt','decrypt']));
        }
        if(!this.keys.has(this.version))fail('INVALID_INPUT','Missing active master key');
        this.storage=o.storage;this.syncDirectory=o.syncDirectory;
    }
    /** Hex, not base64url. VERIFIED: defuss-storage 0.4.1 accepts only portable lowercase names (native-e2e), and lowercasing base64url would make the thumbprint ambiguous. */
    private name(kid:string,generation?:string){
        const thumbprint=unb64(kid,44);
        if(thumbprint.length!==32||generation!==undefined&&!/^[a-f0-9-]{36}$/.test(generation))fail('INVALID_INPUT');
        return 'jwk-'+Array.from(thumbprint,b=>b.toString(16).padStart(2,'0')).join('')+(generation?'.'+generation:'')+'.enc';
    }
    private async key(v:string){const k=this.keys.get(v);if(!k)fail('UNAVAILABLE','Master key version unavailable');return k;}
    private aad(kid:string,generation:string|undefined,version:string){return utf8('defuss-auth/jwk/v2/'+kid+'/'+(generation??'initial')+'/'+version);}
    private async write(kid:string,jwk:JsonWebKey,generation?:string){
        await importPrivate(jwk,kid);
        const nonce=random(12),ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:this.aad(kid,generation,this.version)},await this.key(this.version),utf8(JSON.stringify(jwk)));
        const f=await this.storage.open(this.name(kid,generation),{create:true,exclusive:true});
        try{await f.write(0,utf8(JSON.stringify({v:2,keyVersion:this.version,nonce:b64(nonce),ct:b64(new Uint8Array(ct))})));await f.flush();}finally{await f.close();}
        await this.syncDirectory?.();
    }
    async save(p:KeyPair){if(await jwkThumbprint(p.publicJwk)!==p.kid)fail('INVALID_INPUT');await this.write(p.kid,p.privateJwk);}
    async load(kid:string,generation?:string):Promise<JsonWebKey>{
        try{
            const f=await this.storage.open(this.name(kid,generation),{readOnly:true});let envelope:unknown;
            try{const n=await f.size();if(n<1||n>8192)fail('UNAVAILABLE');envelope=parseJson(text(await f.readExactly(0,n)),8192);}finally{await f.close();}
            if(!object(envelope)||typeof envelope.nonce!=='string'||typeof envelope.ct!=='string')fail('UNAVAILABLE');
            const nonce=unb64(envelope.nonce,16);if(nonce.length!==12)fail('UNAVAILABLE');
            const version=envelope.v===1&&!generation?'legacy':envelope.v===2&&typeof envelope.keyVersion==='string'?keyVersion(envelope.keyVersion):fail('UNAVAILABLE');
            const aad=envelope.v===1?utf8('defuss-auth/jwk/v1/'+kid):this.aad(kid,generation,version);
            const jwk=parseJson(text(new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:aad},await this.key(version),unb64(envelope.ct,8192)))));
            if(!object(jwk)||await jwkThumbprint(jwk as JsonWebKey)!==kid)fail('UNAVAILABLE');
            await importPrivate(jwk as JsonWebKey,kid);return jwk as JsonWebKey;
        }catch(e){throw new Error('Signing key unavailable or corrupt',{cause:e});}
    }
    /** Stage a new encrypted generation. Caller must CAS-publish it in the metadata transaction. */
    async rewrap(kid:string,generation?:string){const jwk=await this.load(kid,generation),next=id();await this.write(kid,jwk,next);return next;}
    /** Only for exclusive offline maintenance; an unpublished file may belong to an in-flight rotation. */
    async reconcile(keep:readonly KeyReference[],limit:number){
        if(!this.storage.list||!this.storage.remove)fail('UNAVAILABLE','Storage cannot reconcile key files');
        const names=new Set(keep.map(k=>this.name(k.kid,k.generation)));let removed=0;
        for(const name of await this.storage.list()){
            if(!/^jwk-[a-f0-9]{64}(?:\.[a-f0-9-]{36})?\.enc$/.test(name)||names.has(name))continue;
            if(await this.storage.remove(name)){if(++removed>=limit)break;}
        }
        await this.syncDirectory?.();return removed;
    }
}
