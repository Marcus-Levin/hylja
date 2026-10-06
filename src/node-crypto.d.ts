// This project does not yet depend on @types/node; declare only the built-in APIs used here.
// `createHash`/`createHmac` are the shared narrow declarations used by the detectors, the sentinel,
// the shadow judge and the release gate; the Ed25519 surface below is used only by the release gate.
// Each function is declared exactly once, with no overload set and no widened parameter or return
// type beyond what its callers pass and read.
declare module 'node:crypto' {
  export function createHash(algorithm: 'sha256'): {
    update(data: string | Uint8Array): { digest(encoding: 'hex'): string };
  };
  /** Native fixed-length constant-time comparison for listener capability digests. */
  export function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean;
  export function createHmac(algorithm: 'sha256', key: Uint8Array): {
    update(data: string | Uint8Array): { digest(encoding: 'hex'): string };
  };
  /** A parsed public or private key. Only the Ed25519 type is used by the release gate. */
  export interface KeyObject {
    readonly type: string;
    readonly asymmetricKeyType?: string;
  }
  export function createPublicKey(input: { key: Uint8Array; format: 'der'; type: 'spki' }): KeyObject;
  export function createPrivateKey(input: { key: Uint8Array; format: 'der'; type: 'pkcs8' }): KeyObject;
  /** RFC 8032 PureEdDSA: a null algorithm selects the key's own scheme. */
  export function sign(algorithm: null, data: Uint8Array, key: KeyObject): Uint8Array;
  export function verify(algorithm: null, data: Uint8Array, key: KeyObject, signature: Uint8Array): boolean;
  export function generateKeyPairSync(type: 'ed25519', options?: {
    publicKeyEncoding?: { format: 'der'; type: 'spki' };
    privateKeyEncoding?: { format: 'der'; type: 'pkcs8' };
  }): { publicKey: Uint8Array; privateKey: Uint8Array };
}
