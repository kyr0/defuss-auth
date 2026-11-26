import { AuthError,fail,jsonCopy,object,type Data,type Json } from './util.js';
export type JsonSchema = boolean | {
    [keyword: string]: unknown;
};
export interface SchemaValidator {
    check(schema: JsonSchema): void;
    validate(schema: JsonSchema, data: Json): void;
}
/** Deliberately strict subset: unsupported assertions fail at startup, never silently pass. */
const annotations = new Set(['$schema', '$id', '$comment', 'title', 'description', 'examples', 'default']);
const types = new Set(['null', 'boolean', 'integer', 'number', 'string', 'object', 'array']);
const limits = new Set(['minLength', 'maxLength', 'minItems', 'maxItems', 'minProperties', 'maxProperties']);
const bounds = new Set(['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum']);
const combinations = new Set(['allOf', 'anyOf', 'oneOf']);
const eq = (a: unknown, b: unknown): boolean => {
    if (a === b)
        return true;
    if (Array.isArray(a) && Array.isArray(b))
        return a.length === b.length && a.every((x, i) => eq(x, b[i]));
    if (object(a) && object(b))
        return Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(k => Object.hasOwn(b, k) && eq(a[k], b[k]));
    return false;
};
function check(s: unknown): void {
    if (typeof s === 'boolean')
        return;
    if (!object(s))
        fail('SCHEMA', 'Invalid schema');
    for (const [k, v] of Object.entries(s)) {
        if (annotations.has(k))
            continue;
        if (k === 'type') {
            const t = Array.isArray(v) ? v : [v];
            if (!t.length || t.some(x => !types.has(x as string)))
                fail('SCHEMA', 'Invalid type');
        }
        else if (k === 'properties') {
            if (!object(v))
                fail('SCHEMA');
            for (const x of Object.values(v))
                check(x);
        }
        else if (k === 'required') {
            if (!Array.isArray(v) || v.some(x => typeof x !== 'string'))
                fail('SCHEMA');
        }
        else if (k === 'additionalProperties' || k === 'items' || k === 'not')
            check(v);
        else if (combinations.has(k)) {
            if (!Array.isArray(v) || !v.length)
                fail('SCHEMA');
            v.forEach(check);
        }
        else if (k === 'enum') {
            if (!Array.isArray(v) || !v.length)
                fail('SCHEMA');
        }
        else if (k === 'const') {
        }
        else if (limits.has(k)) {
            if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0)
                fail('SCHEMA');
        }
        else if (bounds.has(k)) {
            if (typeof v !== 'number' || !Number.isFinite(v))
                fail('SCHEMA');
        }
        else if (k === 'uniqueItems') {
            if (typeof v !== 'boolean')
                fail('SCHEMA');
        }
        else if (k === 'format') {
            if (!['email', 'uri', 'date-time'].includes(v as string))
                fail('SCHEMA', 'Unsupported format');
        }
        else
            fail('SCHEMA', 'Unsupported keyword: ' + k);
    }
}
function matchesType(t: string, v: Json): boolean {
    return t === 'null' ? v === null : t === 'array' ? Array.isArray(v) : t === 'object' ? object(v) : t === 'integer' ? Number.isInteger(v) : typeof v === t;
}
function valid(s: JsonSchema, v: Json): boolean {
    if (typeof s === 'boolean')
        return s;
    for (const [k, a] of Object.entries(s)) {
        if (k === 'type' && !(Array.isArray(a) ? a : [a]).some(t => matchesType(t as string, v)))
            return false;
        if (k === 'const' && !eq(a, v))
            return false;
        if (k === 'enum' && !(a as Json[]).some(x => eq(x, v)))
            return false;
        if (combinations.has(k)) {
            const n = (a as JsonSchema[]).filter(x => valid(x, v)).length;
            if (k === 'allOf' && n !== (a as JsonSchema[]).length || k === 'anyOf' && !n || k === 'oneOf' && n !== 1)
                return false;
        }
        if (k === 'not' && valid(a as JsonSchema, v))
            return false;
        if (typeof v === 'number') {
            if (k === 'minimum' && v < (a as number) || k === 'maximum' && v > (a as number) || k === 'exclusiveMinimum' && v <= (a as number) || k === 'exclusiveMaximum' && v >= (a as number))
                return false;
        }
        if (typeof v === 'string') {
            const n = [...v].length;
            if (k === 'minLength' && n < (a as number) || k === 'maxLength' && n > (a as number))
                return false;
            if (k === 'format') {
                if (a === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))
                    return false;
                if (a === 'uri') {
                    try {
                        new URL(v);
                    }
                    catch {
                        return false;
                    }
                }
                if (a === 'date-time' && (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/i.test(v) || !Number.isFinite(Date.parse(v))))
                    return false;
            }
        }
        if (Array.isArray(v)) {
            if (k === 'minItems' && v.length < (a as number) || k === 'maxItems' && v.length > (a as number))
                return false;
            if (k === 'items' && !v.every(x => valid(a as JsonSchema, x)))
                return false;
            if (k === 'uniqueItems' && a === true) {
                if (v.length > 1024)
                    fail('SCHEMA', 'uniqueItems budget exceeded');
                if (v.some((x, i) => v.slice(0, i).some(y => eq(x, y))))
                    return false;
            }
        }
        if (object(v)) {
            const o = v as Data;
            if (k === 'required' && !(a as string[]).every(x => Object.hasOwn(o, x)))
                return false;
            if (k === 'minProperties' && Object.keys(o).length < (a as number) || k === 'maxProperties' && Object.keys(o).length > (a as number))
                return false;
            if (k === 'properties' && Object.entries(a as Record<string, JsonSchema>).some(([p, sc]) => Object.hasOwn(o, p) && !valid(sc, o[p]!)))
                return false;
            if (k === 'additionalProperties') {
                for (const p of Object.keys(o))
                    if (!Object.hasOwn((s.properties ?? {}) as object, p) && !valid(a as JsonSchema, o[p]!))
                        return false;
            }
        }
    }
    return true;
}
export interface SchemaIssue {path:string;keyword:string;message:string;}
export class SchemaValidationError extends AuthError {
    constructor(readonly issues:readonly SchemaIssue[]){super('SCHEMA','Data does not satisfy configured schema');}
}
type Check=(value:Json,path:string,issues:SchemaIssue[])=>boolean;
const pointer=(p:string,k:string)=>p+'/'+k.replace(/~/g,'~0').replace(/\//g,'~1');
function compile(s:JsonSchema):Check {
    if(typeof s==='boolean')return (_v,p,out)=>s||addIssue(out,p,'false');
    const checks:Check[]=[];
    for(const [keyword,a] of Object.entries(s)){
        if(annotations.has(keyword))continue;
        if(keyword==='properties'){
            const properties=Object.entries(a as Record<string,JsonSchema>).map(([k,v])=>[k,compile(v)] as const);
            checks.push((v,p,out)=>{if(!object(v))return true;let ok=true;for(const [k,check] of properties)if(Object.hasOwn(v,k)&&!check((v as Data)[k]!,pointer(p,k),out))ok=false;return ok;});
        }else if(keyword==='required'){
            const keys=a as string[];checks.push((v,p,out)=>{if(!object(v))return true;let ok=true;for(const k of keys)if(!Object.hasOwn(v,k)){addIssue(out,pointer(p,k),keyword);ok=false;}return ok;});
        }else if(keyword==='additionalProperties'){
            const known=new Set(Object.keys((s.properties??{}) as object)),check=compile(a as JsonSchema);checks.push((v,p,out)=>{if(!object(v))return true;let ok=true;for(const k of Object.keys(v))if(!known.has(k)&&!check((v as Data)[k]!,pointer(p,k),out)){ok=false;}return ok;});
        }else if(keyword==='items'){
            const item=compile(a as JsonSchema);checks.push((v,p,out)=>{if(!Array.isArray(v))return true;let ok=true;for(let i=0;i<v.length;i++)if(!item(v[i]!,pointer(p,String(i)),out))ok=false;return ok;});
        }else if(combinations.has(keyword)){
            const subs=(a as JsonSchema[]).map(compile);checks.push((v,p,out)=>{const n=subs.filter(check=>check(v,p,[])).length;return (keyword==='allOf'?n===subs.length:keyword==='oneOf'?n===1:n>0)||addIssue(out,p,keyword);});
        }else if(keyword==='not'){
            const sub=compile(a as JsonSchema);checks.push((v,p,out)=>!sub(v,p,[])||addIssue(out,p,keyword));
        }else{
            // Scalar assertions reuse the audited, strict predicate. Compile their constant input once.
            const assertion={[keyword]:a};checks.push((v,p,out)=>valid(assertion,v)||addIssue(out,p,keyword));
        }
    }
    return (v,p,out)=>{let ok=true;for(const check of checks)if(!check(v,p,out))ok=false;return ok;};
}
function addIssue(out:SchemaIssue[],path:string,keyword:string):false{if(out.length<32)out.push({path,keyword,message:'Constraint not satisfied'});return false;}
/** Per-authority compiler. Never generates or evaluates code. */
export function createStrictSchemaValidator():SchemaValidator{
    const compiled=new WeakMap<object,Check>();
    return {check(s){const snapshot=jsonCopy(s);check(snapshot);if(typeof s==='object')compiled.set(s,compile(snapshot as JsonSchema));},validate(s,v){let fn=typeof s==='object'?compiled.get(s):undefined;if(!fn){check(s);fn=compile(s);}const issues:SchemaIssue[]=[];if(!fn(v,'',issues))throw new SchemaValidationError(issues);}};
}
export const strictSchemaValidator=createStrictSchemaValidator();
/** Adapt a caller-configured Ajv 2020-compatible compiler; no dynamic network references or coercion. */
export function createCompiledSchemaValidator(compiler: {
    compile(schema: JsonSchema): (value: unknown) => boolean;
}): SchemaValidator {
    const compiled = new Map<JsonSchema, (value: unknown) => boolean>();
    return {
        check(schema) {
            const validate = compiler.compile(schema);
            compiled.set(schema, validate);
        },
        validate(schema, value) {
            const validate = compiled.get(schema);
            if (!validate)
                fail('SCHEMA', 'Schema was not compiled');
            if (validate(value) !== true)
                fail('SCHEMA', 'Data does not satisfy configured schema');
        },
    };
}

/** A conservative TypeScript projection of common JSON Schema assertions. Runtime validation remains authoritative. */
export type SchemaSet=Partial<Record<'user'|'tenant'|'service'|'tokenData',JsonSchema>>;
type PrimitiveType<T> = T extends 'string'?string:T extends 'number'|'integer'?number:T extends 'boolean'?boolean:T extends 'null'?null:T extends 'array'?Json[]:T extends 'object'?Data:Json;
type RequiredKeys<S> = S extends {readonly required:readonly (infer K extends string)[]}?K:never;
type ObjectSchema<S,P extends Record<string,unknown>> = {[K in keyof P as K extends RequiredKeys<S>?K:never]:InferSchema<P[K]>} & {[K in keyof P as K extends RequiredKeys<S>?never:K]?:InferSchema<P[K]>};
export type InferSchema<S> = S extends {readonly const:infer V}?V:S extends {readonly enum:readonly (infer V)[]}?V:S extends {readonly anyOf:readonly (infer V)[]}?InferSchema<V>:S extends {readonly oneOf:readonly (infer V)[]}?InferSchema<V>:S extends {readonly type:'object';readonly properties:infer P extends Record<string,unknown>}?ObjectSchema<S,P>:S extends {readonly type:'array';readonly items:infer I}?InferSchema<I>[]:S extends {readonly type:infer T}?PrimitiveType<T extends readonly unknown[]?T[number]:T>:Json;
export type SchemaData<S extends SchemaSet,K extends keyof SchemaSet> = K extends keyof S ? InferSchema<S[K]> extends Data ? InferSchema<S[K]> : Data : Data;
