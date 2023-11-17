import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_scalarmult_ed25519_BYTES =
  constants.crypto_scalarmult_ed25519_BYTES;
export const crypto_scalarmult_ed25519_SCALARBYTES =
  constants.crypto_scalarmult_ed25519_SCALARBYTES;
export const crypto_scalarmult_BYTES = constants.crypto_scalarmult_BYTES;
export const crypto_scalarmult_SCALARBYTES =
  constants.crypto_scalarmult_SCALARBYTES;

/**
 * Derives a shared secret from a local secret key and a remote public key.
 * https://sodium-friends.github.io/docs/docs/diffiehellman#crypto_scalarmult
 */
export function crypto_scalarmult(
  q: Uint8Array,
  scalar: Uint8Array,
  p: Uint8Array
) {
  const nativeResult = Libsodium.crypto_scalarmult(
    ...Array.from([q, scalar, p], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_scalarmult execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}

/**
 * Creates a scalar multiplication public key based on a secret key.
 * https://sodium-friends.github.io/docs/docs/diffiehellman#crypto_scalarmult_base
 */
export function crypto_scalarmult_base(q: Uint8Array, scalar: Uint8Array) {
  const nativeResult = Libsodium.crypto_scalarmult_base(
    ...Array.from([q, scalar], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_scalarmult_base execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}

/**
 * Multiplies point p by scalar n and stores its compressed representation in q.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_scalarmult_ed25519
 */
export function crypto_scalarmult_ed25519(
  q: Uint8Array,
  scalar: Uint8Array,
  p: Uint8Array
) {
  const nativeResult = Libsodium.crypto_scalarmult_ed25519(
    ...Array.from([q, scalar, p], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_scalarmult_ed25519 execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}

/**
 * Multiplies point p by scalar n and stores its compressed representation in q. This version does not clamp.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_scalarmult_ed25519_noclamp
 */
export function crypto_scalarmult_ed25519_noclamp(
  q: Uint8Array,
  scalar: Uint8Array,
  p: Uint8Array
) {
  const nativeResult = Libsodium.crypto_scalarmult_ed25519_noclamp(
    ...Array.from([q, scalar, p], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_scalarmult_ed25519_noclamp execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}

/**
 * Multiplies the base point by scalar n and stores its compressed representation in q. Note that n will be clamped.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_scalarmult_ed25519_base
 */
export function crypto_scalarmult_ed25519_base(
  q: Uint8Array,
  scalar: Uint8Array
) {
  const nativeResult = Libsodium.crypto_scalarmult_ed25519_base(
    ...Array.from([q, scalar], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_scalarmult_ed25519_base execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}

/**
 * Multiplies the base point by scalar n and stores its compressed representation in q. This version does not clamp.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_scalarmult_ed25519_base_noclamp
 */
export function crypto_scalarmult_ed25519_base_noclamp(
  q: Uint8Array,
  scalar: Uint8Array
) {
  const nativeResult = Libsodium.crypto_scalarmult_ed25519_base_noclamp(
    ...Array.from([q, scalar], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_scalarmult_ed25519_base_noclamp execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  q.set(res);
}
