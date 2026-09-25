// This project does not yet depend on @types/node; declare only the built-in API used for
// deterministic, unkeyed replay fingerprints. These hashes are NOT authorization tokens.
declare module 'node:crypto' {
  export function createHash(algorithm: 'sha256'): {
    update(data: string): { digest(encoding: 'hex'): string };
  };
}
