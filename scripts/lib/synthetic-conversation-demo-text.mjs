/**
 * The two fixed operator-facing lines of the #250 synthetic conversation demo, with no imports at all.
 *
 * They live in a module of their own so the operator entry point can print the fixed decline on EVERY exit
 * path - including one where the accepted runtime or the worker observation could not even be loaded -
 * without depending on anything that can fail. They carry no value, no argument, no native error text, no
 * code, no signal name and no path, and nothing is ever appended to them. The case module re-exports them,
 * so the operator command and the test-only fault driver still print identical bytes.
 */

/** The fixed text a malformed invocation gets. */
export const DEMO_ARGUMENT_REFUSED = 'hylja synthetic conversation demo: argument refused\n'
  + 'expected: no arguments, or --case default | --case blocked-reply | --case unsupported-request\n';

/** The fixed line an unexpected outcome gets. No native error, no planted value, no signal name. */
export const DEMO_DECLINED = 'hylja synthetic conversation demo: the case did not match its declared behaviour\n';
