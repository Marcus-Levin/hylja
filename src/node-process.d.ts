// Minimal process surface for the release-gate CLI and the fixed egress sentinel worker; no
// @types/node dependency. `execPath` is the absolute interpreter the sentinel runner spawns, `stdin`
// is the capped byte stream the worker reads one framed request from, and `stdout.write` accepts the
// framed reply bytes. Nothing here widens the process object: there is no dynamic or global merge.
declare const process: {
  readonly argv: readonly string[];
  readonly execPath: string;
  exitCode?: number;
  readonly stdin: {
    on(event: 'data', listener: (chunk: Uint8Array) => void): void;
    on(event: 'end', listener: () => void): void;
    on(event: 'error', listener: (error: Error) => void): void;
  } | null;
  readonly stdout: { write(chunk: string | Uint8Array): boolean };
  readonly stderr: { write(chunk: string): boolean };
};