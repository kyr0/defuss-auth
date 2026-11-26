// OFFLINE compiler bridge only. Actual pkgroll build uses the installed upstream declarations.
declare module 'defuss-db/server' { export function openDirectory(directory:string,options?:Record<string,unknown>):Promise<unknown>; }
declare module 'defuss-db/browser' { export function openOPFS(options?:Record<string,unknown>):Promise<unknown>; }
declare module 'defuss-storage/node' { export function createFileStorage(directory:string,options?:Record<string,unknown>):Promise<import('../../src/keys.js').ByteStorage>; }
declare module 'defuss-storage/opfs' { export function createOPFSStorage(options?:Record<string,unknown>):Promise<import('../../src/keys.js').ByteStorage>; }
