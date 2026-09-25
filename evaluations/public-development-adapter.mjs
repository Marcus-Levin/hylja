// Evaluation-only public D01/D02/D05 bridge. Not a policy, transport, scorer or release gate.
// Compileable RED checkpoint: behavioral implementation follows the tests.
const unsupported = () => { throw new TypeError('Invalid public development adapter input'); };

export function projectPublicDevelopmentFixture(_fixture, _localSink) {
  return Object.freeze({ developmentCase: Object.freeze({ fields: [] }), fieldRefForSourcePointer: () => undefined });
}

export function serializeControlledRelease(_fields, _localSink) {
  return unsupported();
}

export async function runPublicReferenceCandidate(_options) {
  return unsupported();
}
