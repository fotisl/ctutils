/**
 * Certificate Transparency Utilities
 * Common helper functions
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * Convert an uint64 to an ArrayBuffer with big-endian encoding.
 * @param {number} num - The number to convert.
 * @return {ArrayBuffer} An ArrayBuffer containing the number.
 */
export function uint64ToArrayBuffer(num) {
  const ret = new ArrayBuffer(8);
  const retView = new Uint8Array(ret);

  for(let i = 0; i < 8; i++)
    retView[i] = ~~(num / (2 ** (8 * (7 - i)))) & 0xff;

  return ret;
}

/**
 * Convert the contents of an ArrayBuffer to an uint64 with big-endian encoding.
 * The ArrayBuffer must have at least 8 bytes, the rest are ignored.
 * @param {ArrayBuffer} buf - The ArrayBuffer.
 * @return {number} The unsigned 64 bit integer.
 */
export function arrayBufferToUint64(buf) {
  let ret = 0;
  const bufView = new Uint8Array(buf);

  for(let i = 0; i < 8; i++)
    ret += bufView[i] * (2 ** (8 * (7 - i)));

  return ret;
}

/**
 * Create a query string from an object with parameters.
 * @param {Object} params - The object with the parameters.
 * @return {string} The resulting string.
 */
export function paramsToQueryString(params) {
  return Object.keys(params).map(k =>
    encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&');
}
