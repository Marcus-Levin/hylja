declare module 'node:child_process' {
  /**
   * Minimal child-process surface for the bounded local Presidio worker and the fixed egress sentinel
   * worker. This project does not depend on @types/node; only the four events and two stream methods
   * these modules actually use are declared, with no `any` and no overload set. The sentinel runner
   * writes one already-framed `Uint8Array`, which is why `write` accepts bytes as well as text.
   */
  export interface WorkerStream {
    on(event: 'data', listener: (chunk: Uint8Array) => void): void;
  }
  export interface WorkerStdin {
    write(chunk: string | Uint8Array): boolean;
    end(): void;
    destroy(): void;
    on(event: 'error', listener: (error: Error) => void): void;
  }
  export interface WorkerChild {
    readonly stdin: WorkerStdin | null;
    readonly stdout: WorkerStream | null;
    readonly stderr: WorkerStream | null;
    /** `error` delivers an Error; `close` delivers a nullable exit code and a nullable signal. */
    on(event: 'error' | 'close', listener: (first: Error | number | null, second?: string | null) => void): void;
    kill(signal?: string): boolean;
  }
  export function spawn(command: string, args: readonly string[], options: {
    stdio: readonly ['pipe', 'pipe', 'pipe'];
    env: Record<string, string>;
    cwd?: string;
    windowsHide?: boolean;
  }): WorkerChild;
}
/**
 * Timers are declared module-scoped rather than globally. A global `setTimeout` declaration here would
 * merge with the ambient one for the whole program and change its return type, so any later
 * `const t: number = setTimeout(...)` in `src/` would stop compiling for everyone. `node:timers` is the
 * real Node surface and needs no global merge.
 */
declare module 'node:timers' {
  export interface WorkerTimer { unref(): void }
  export function setTimeout(handler: () => void, timeout: number): WorkerTimer;
  export function clearTimeout(handle: WorkerTimer): void;
}
