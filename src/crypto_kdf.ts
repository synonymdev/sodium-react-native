import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_kdf_KEYBYTES = constants.crypto_kdf_KEYBYTES;
export const crypto_kdf_BYTES_MIN = constants.crypto_kdf_BYTES_MIN;
export const crypto_kdf_BYTES_MAX = constants.crypto_kdf_BYTES_MAX;
export const crypto_kdf_CONTEXTBYTES = constants.crypto_kdf_CONTEXTBYTES;

/**
 * Generates a new master key.
 * https://sodium-friends.github.io/docs/docs/keyderivation#crypto_kdf_keygen
 */
export function crypto_kdf_keygen(key: Uint8Array) {
  const nativeResult = Libsodium.crypto_kdf_keygen(Array.from(key));
  const res = new Uint8Array(nativeResult);
  key.set(res);
}

/**
 * Derives a new key from a master key.
 * https://sodium-friends.github.io/docs/docs/keyderivation#crypto_kdf_derive_from_key
 */
export function crypto_kdf_derive_from_key(
  subkey: Uint8Array,
  subkeyId: number,
  ctx: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_kdf_derive_from_key(
    ...Array.from([subkey, subkeyId, ctx, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_kdf_derive_from_key execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  subkey.set(res);
}
