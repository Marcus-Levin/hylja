// Minimal file-system surface for the release-gate CLI; this project does not depend on @types/node.
declare module 'node:fs' {
  export interface Stats {
    readonly size: number;
    readonly nlink: number;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  }
  export const constants: { readonly O_RDONLY: number; readonly O_NOFOLLOW: number; readonly O_NONBLOCK: number };
  export function lstatSync(path: string): Stats;
  export function fstatSync(descriptor: number): Stats;
  export function realpathSync(path: string): string;
  export function openSync(path: string, flags: number): number;
  export function closeSync(descriptor: number): void;
  export function readFileSync(descriptor: number): Uint8Array;
}
declare module 'node:path' {
  export function resolve(...parts: string[]): string;
  export function join(...parts: string[]): string;
  export function basename(path: string): string;
  export function isAbsolute(path: string): boolean;
}
