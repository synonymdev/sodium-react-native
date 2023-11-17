import { vn } from './helpers';

export function sodium_malloc(n: Uint8Array) {
  return new Uint8Array(n);
}

export function sodium_free(n: Uint8Array) {
  sodium_memzero(n);
}

/**
 * Zeros out the data in buf.
 * https://sodium-friends.github.io/docs/docs/helpers#sodium_memzero
 */
export function sodium_memzero(arr: Uint8Array) {
  arr.fill(0);
}

/**
 * Compares a with b, in constant-time for a.length.
 * https://sodium-friends.github.io/docs/docs/helpers#sodium_memcmp
 */
export function sodium_memcmp(a: Uint8Array, b: Uint8Array) {
  return vn(a, 0, b, 0, a.byteLength) === 0 && a.byteLength === b.byteLength;
}
