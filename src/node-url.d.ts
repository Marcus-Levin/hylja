// Minimal url surface for the release-gate CLI entry-point guard and for resolving the fixed egress
// sentinel worker next to its parent module; no @types/node dependency.
declare module 'node:url' {
  export function pathToFileURL(path: string): { href: string };
  export function fileURLToPath(url: URL | string): string;
}