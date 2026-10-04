// This project does not yet depend on @types/node; declare only the built-in APIs the mapping AEAD
// primitive uses. These declarations are deliberately separate from the shared `node:crypto` surface
// in `node-crypto.d.ts`: `createHash`, `createHmac`, the `KeyObject` interface, `createPublicKey`,
// `createPrivateKey`, `sign`, `verify` and `generateKeyPairSync` are declared there exactly once and
// are not repeated here. Each function below is declared once, with no overload set and no widened
// parameter or return type beyond what `src/mapping-aead.ts` passes and reads.
declare module 'node:crypto' {
  /** Cryptographically secure random bytes. This module never derives a nonce or a key from input. */
  export function randomBytes(size: number): Uint8Array;
  export function createCipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array): {
    setAAD(aad: Uint8Array, options: { plaintextLength: number }): void;
    update(data: Uint8Array): Uint8Array;
    final(): Uint8Array;
    /** The full 16-byte GCM authentication tag. */
    getAuthTag(): Uint8Array;
  };
  export function createDecipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array): {
    setAAD(aad: Uint8Array, options: { plaintextLength: number }): void;
    /** Returns unauthenticated bytes; the caller must not expose them before `final` succeeds. */
    update(data: Uint8Array): Uint8Array;
    setAuthTag(tag: Uint8Array): void;
    /** Throws when the tag does not authenticate; the message and cause are never surfaced. */
    final(): Uint8Array;
  };
}
