// Minimal loopback-socket surface for the bounded local conversation owner; this project does not
// depend on @types/node. Only the four events and the three calls that module actually uses are
// declared, with no `any` and no overload set: the owner connects to one captured numeric loopback
// endpoint, writes one already-checked image, and reads one bounded reply.
declare module 'node:net' {
  /** One listener signature per event the owner registers, so no call site needs a cast. */
  export interface LoopbackSocketEvents {
    connect: () => void;
    data: (chunk: Uint8Array) => void;
    error: (error: Error) => void;
    close: () => void;
  }
  export interface LoopbackSocket {
    /** Undefined until the connection is established; the owner reads these only inside `connect`. */
    readonly remoteAddress: string | undefined;
    readonly remotePort: number | undefined;
    readonly remoteFamily: string | undefined;
    readonly localAddress: string | undefined;
    readonly destroyed: boolean;
    readonly writable: boolean;
    /** Zero until the owner's single synchronous handoff writes; it is read as that handoff's guard. */
    readonly bytesWritten: number;
    on<K extends keyof LoopbackSocketEvents>(event: K, listener: LoopbackSocketEvents[K]): void;
    write(chunk: Uint8Array): boolean;
    end(): void;
    destroy(): void;
  }
  export function createConnection(options: {
    readonly port: number;
    /** A numeric IPv4 literal in the owner's own constant, so no name resolution is ever started. */
    readonly host: string;
    readonly localAddress: string;
    readonly family: 4;
  }): LoopbackSocket;
}