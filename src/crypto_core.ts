import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_core_ed25519_SCALARBYTES =
  constants.crypto_core_ed25519_SCALARBYTES;
export const crypto_core_ed25519_BYTES = constants.crypto_core_ed25519_BYTES;
export const crypto_core_ed25519_UNIFORMBYTES =
  constants.crypto_core_ed25519_UNIFORMBYTES;

/**
 * Generates random scalar in ]0..L[ and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_scalar_random
 */
export function crypto_core_ed25519_scalar_random(random: Uint8Array) {
  const nativeResult = Libsodium.crypto_core_ed25519_scalar_random(
    Array.from(random)
  );
  const res = new Uint8Array(nativeResult);
  random.set(res);
}

/**
 * Adds point q to p and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_add
 */
export function crypto_core_ed25519_add(
  r: Uint8Array,
  p: Uint8Array,
  q: Uint8Array
) {
  const nativeResult = Libsodium.crypto_core_ed25519_add(
    ...Array.from([r, p, q], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_add execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  r.set(res);
}

/**
 * Subtracts point q to p and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_sub
 */
export function crypto_core_ed25519_sub(
  r: Uint8Array,
  p: Uint8Array,
  q: Uint8Array
) {
  const nativeResult = Libsodium.crypto_core_ed25519_sub(
    ...Array.from([r, p, q], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_sub execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  r.set(res);
}

/**
 * Maps a crypto_core_ed25519_UNIFORMBYTES bytes vector (usually the output of a hash function) to a valid curve point and stores its compressed representation in p.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_from_uniform
 */
export function crypto_core_ed25519_from_uniform(p: Uint8Array, r: Uint8Array) {
  const nativeResult = Libsodium.crypto_core_ed25519_from_uniform(
    ...Array.from([p, r], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_from_uniform execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  p.set(res);
}
