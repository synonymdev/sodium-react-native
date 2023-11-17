import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_generichash_STATEBYTES =
  constants.crypto_generichash_STATEBYTES;
export const crypto_generichash_KEYBYTES =
  constants.crypto_generichash_KEYBYTES;
export const crypto_generichash_KEYBYTES_MIN =
  constants.crypto_generichash_KEYBYTES_MIN;
export const crypto_generichash_KEYBYTES_MAX =
  constants.crypto_generichash_KEYBYTES_MAX;
export const crypto_generichash_BYTES = constants.crypto_generichash_BYTES;
export const crypto_generichash_BYTES_MIN =
  constants.crypto_generichash_BYTES_MIN;
export const crypto_generichash_BYTES_MAX =
  constants.crypto_generichash_BYTES_MAX;

/**
 * Hashes a value with an optional key using the generichash method.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash
 */
export function crypto_generichash(
  out: Uint8Array,
  input: Uint8Array,
  key?: Uint8Array
) {
  if (!key) key = new Uint8Array(0);

  const nativeResult = Libsodium.crypto_generichash(
    ...Array.from([out, input, key], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  out.set(res);
}

/**
 * Same as crypto_generichash, except that this hashes an array of buffer's instead of a single one.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_batch
 */
export function crypto_generichash_batch(
  out: Uint8Array,
  batch: Uint8Array[],
  key?: Uint8Array
) {
  if (!key) key = new Uint8Array(0);

  const state = new Uint8Array(384);
  crypto_generichash_init(state, key, out.byteLength);
  batch.forEach((item) => crypto_generichash_update(state, item));
  crypto_generichash_final(state, out);
}

/**
 * Initialise a new hash state with an optional key and the desired output length.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_init
 */
export function crypto_generichash_init(
  state: Uint8Array,
  key: Uint8Array,
  outlen: number
) {
  const nativeResult = Libsodium.crypto_generichash_init(
    ...Array.from([state, key, outlen], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_init execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  state.set(res);
}

/**
 * Update a hash state with a given input.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_update
 */
export function crypto_generichash_update(
  state: Uint8Array,
  input: Uint8Array
) {
  const nativeResult = Libsodium.crypto_generichash_update(
    ...Array.from([state, input], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_update execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  state.set(res);
}

/**
 * Finalize a given hash state and write the digest to output buffer.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_final
 */
export function crypto_generichash_final(state: Uint8Array, out: Uint8Array) {
  const nativeResult = Libsodium.crypto_generichash_final(
    ...Array.from([state, out], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_final execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}
