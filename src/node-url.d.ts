// Minimal url surface for the release-gate CLI entry-point guard; no @types/node dependency.
declare module 'node:url' {
  export function pathToFileURL(path: string): { href: string };
}
