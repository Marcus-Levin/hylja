/**
 * Strict bounded byte/text encodings for release evidence.
 *
 * `decodeBase64Strict` implements the RFC 4648 section 4 alphabet with canonical padding only and
 * rejects non-canonical trailing bits, so one encoding has exactly one accepted byte string. It is
 * written out rather than delegated to a lenient decoder because the release gate must not accept
 * two encodings of one signature or public key.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const VALUES: Readonly<Record<string, number>> = Object.freeze(Object.fromEntries(
  [...ALPHABET].map((character, index) => [character, index]),
));
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const LOWER_HEX = /^[0-9a-f]+$/;

/** True only for lowercase hex of exactly `length` characters. */
export function isLowerHex(value: string, length: number): boolean {
  return value.length === length && LOWER_HEX.test(value);
}

/** Decode canonical base64, or return null. `maxLength` bounds the decoded size. */
export function decodeBase64Strict(text: string, maxLength: number): Uint8Array | null {
  if (typeof text !== 'string' || text.length === 0 || text.length % 4 !== 0) return null;
  if (!BASE64.test(text)) return null;
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  if ((text.length / 4) * 3 - padding > maxLength) return null;
  const body = padding === 0 ? text : text.slice(0, text.length - padding);
  const bytes = new Uint8Array((text.length / 4) * 3 - padding);
  let offset = 0;
  for (let index = 0; index < body.length; index += 4) {
    const a = VALUES[body[index] as string];
    const b = VALUES[body[index + 1] as string];
    const c = index + 2 < body.length ? VALUES[body[index + 2] as string] : undefined;
    const d = index + 3 < body.length ? VALUES[body[index + 3] as string] : undefined;
    if (a === undefined || b === undefined || (padding === 0 && (c === undefined || d === undefined))) return null;
    // Reject a final group whose unused low bits are not zero: one byte string, one encoding.
    if (c === undefined && (b & 0x0f) !== 0) return null;
    if (c !== undefined && d === undefined && (c & 0x03) !== 0) return null;
    const group = (a << 18) | (b << 12) | ((c ?? 0) << 6) | (d ?? 0);
    if (offset < bytes.length) bytes[offset++] = (group >> 16) & 0xff;
    if (offset < bytes.length) bytes[offset++] = (group >> 8) & 0xff;
    if (offset < bytes.length) bytes[offset++] = group & 0xff;
  }
  return offset === bytes.length ? bytes : null;
}
