// This project does not yet depend on @types/node; declare only the built-in APIs used here.
// `types.isProxy` and `types.isUint8Array` are the existing Node intrinsic brand checks the scoped
// entity reference derivation needs to reject a proxied or spoofed key without running its traps. They
// are the only two members declared, with no overload set and no widened type beyond what it passes.
declare module 'node:util' {
  /** The intrinsic brand checks this project uses. Only these two members are declared. */
  export interface NodeUtilTypes {
    /** True for any Proxy, revoked or not, checked without invoking a trap. */
    isProxy(value: unknown): boolean;
    /** True only for a genuine Uint8Array, never for a view that spoofs Symbol.toStringTag. */
    isUint8Array(value: unknown): boolean;
  }
  export const types: NodeUtilTypes;
}
