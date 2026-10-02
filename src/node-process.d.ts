// Minimal process surface for the release-gate CLI; this project does not depend on @types/node.
declare const process: {
  readonly argv: readonly string[];
  exitCode?: number;
  readonly stdout: { write(chunk: string): boolean };
  readonly stderr: { write(chunk: string): boolean };
};
