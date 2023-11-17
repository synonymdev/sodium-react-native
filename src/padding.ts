import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';

/**
 * Pads buf with random data from index unpaddedLength up to closest multiple of blocksize.
 * https://sodium-friends.github.io/docs/docs/padding#sodium_pad
 */
export function sodium_pad(
  buf: Uint8Array,
  unpaddedLength: number,
  blocksize: number
) {
  const nativeResult = Libsodium.sodium_pad(
    ...Array.from([buf, unpaddedLength, blocksize], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`sodium_pad execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  buf.set(res);
  return nativeResult.length;
}

/**
 * Calculates unpaddedLength from a padded buf with blocksize.
 * https://sodium-friends.github.io/docs/docs/padding#sodium_unpad
 */
export function sodium_unpad(
  buf: Uint8Array,
  unpaddedLength: number,
  blocksize: number
) {
  const nativeResult = Libsodium.sodium_unpad(
    ...Array.from([buf, unpaddedLength, blocksize], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`sodium_unpad execution failed: ${nativeResult}.`);
  }
  return nativeResult;
}
