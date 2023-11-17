import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_hash_sha512_BYTES = constants.crypto_hash_sha512_BYTES;

/**
 * Hashes a value to a short hash based on a key.
 * https://sodium-friends.github.io/docs/docs/sha#crypto_hash_sha512
 */
export function crypto_hash_sha512(out: Uint8Array, input: Uint8Array) {
  const nativeResult = Libsodium.crypto_hash_sha512(
    ...Array.from([out, input], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_hash_sha512 execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}
