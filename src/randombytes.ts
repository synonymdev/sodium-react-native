import { Libsodium } from './libsodium';

/**
 * Fills buf with random data.
 * https://sodium-friends.github.io/docs/docs/generatingrandomdata#randombytes_buf
 */
export function randombytes_buf(arr: Uint8Array) {
  const nativeResult = Libsodium.randombytes_buf(Array.from(arr));
  const res = new Uint8Array(nativeResult);
  arr.set(res);
}
