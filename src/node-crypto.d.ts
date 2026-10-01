// This project does not yet depend on @types/node; declare only the built-in API used for
// deterministic, unkeyed replay fingerprints and keyed secret fingerprints. Neither is an authorization token.
declare module 'node:crypto' {
  export function createHash(algorithm: 'sha256'): {
    update(data: string | Uint8Array): { digest(encoding: 'hex'): string };
  };
  export function createHmac(algorithm: 'sha256', key: Uint8Array): {
    update(data: string | Uint8Array): { digest(encoding: 'hex'): string };
  };
}
