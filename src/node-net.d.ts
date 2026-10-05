// Minimal native loopback socket/server surface for the conversation owner and local listener.
// This project does not depend on @types/node. Only used events, calls and fields are declared,
// with no `any` or overload set; the listener adds server lifecycle and bounded write completion.
declare module 'node:net' {
  /** One listener signature per event the owner registers, so no call site needs a cast. */
  export interface LoopbackSocketEvents {
    connect: () => void;
    data: (chunk: Uint8Array) => void;
    error: (error: Error) => void;
    close: () => void;
    end: () => void;
  }
  export interface LoopbackSocket {
    /** Undefined until the connection is established; the owner reads these only inside `connect`. */
    readonly remoteAddress: string | undefined;
    readonly remotePort: number | undefined;
    readonly remoteFamily: string | undefined;
    readonly localAddress: string | undefined;
    readonly destroyed: boolean;
    /** True while the kernel handshake is still outstanding; the owner refuses to write before it clears. */
    readonly connecting: boolean;
    readonly writable: boolean;
    /** Zero until the owner's single synchronous handoff writes; it is read as that handoff's guard. */
    readonly bytesWritten: number;
    on<K extends keyof LoopbackSocketEvents>(event: K, listener: LoopbackSocketEvents[K]): void;
    write(chunk: Uint8Array, callback?: (error?: Error) => void): boolean;
    end(): void;
    destroy(): void;
  }
  export interface LoopbackServer {
    listen(options: { port: number; host: string }, callback: () => void): void;
    close(callback: () => void): void;
    address(): { port: number; address: string; family: string } | string | null;
    on(event: 'error', listener: () => void): void;
  }
  export function createServer(options: { allowHalfOpen: boolean },
    listener: (socket: LoopbackSocket) => void): LoopbackServer;
  export function createConnection(options: {
    readonly port: number;
    /** A numeric IPv4 literal in the owner's own constant, so no name resolution is ever started. */
    readonly host: string;
    readonly localAddress: string;
    readonly family: 4;
  }): LoopbackSocket;
}