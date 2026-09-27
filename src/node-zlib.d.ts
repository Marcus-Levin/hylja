// This project does not yet depend on @types/node; declare only the bounded inflate calls the egress sentinel
// uses to look inside compressed payloads.
declare module 'node:zlib' {
  interface InflateOptions { maxOutputLength?: number; finishFlush?: number }
  export function gunzipSync(data: Uint8Array, options?: InflateOptions): Uint8Array;
  export function inflateSync(data: Uint8Array, options?: InflateOptions): Uint8Array;
  export function inflateRawSync(data: Uint8Array, options?: InflateOptions): Uint8Array;
  export function brotliDecompressSync(data: Uint8Array, options?: InflateOptions): Uint8Array;
}
