import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_sign_BYTES = constants.crypto_sign_BYTES;
export const crypto_sign_SEEDBYTES = constants.crypto_sign_SEEDBYTES;
export const crypto_sign_PUBLICKEYBYTES = constants.crypto_sign_PUBLICKEYBYTES;
export const crypto_sign_SECRETKEYBYTES = constants.crypto_sign_SECRETKEYBYTES;

/**
 * Creates a new keypair.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_keypair
 */
export function crypto_sign_keypair(pk: Uint8Array, sk: Uint8Array) {
  const nativeResult = Libsodium.crypto_sign_keypair(
    ...Array.from([pk, sk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_sign_keypair execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);

  pk.set(res.subarray(0, constants.crypto_sign_PUBLICKEYBYTES));
  sk.set(res.subarray(constants.crypto_sign_PUBLICKEYBYTES));
}

/**
 * Creates a new keypair based on a seed.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_seed25519_keypair
 */
export function crypto_sign_seed_keypair(
  pk: Uint8Array,
  sk: Uint8Array,
  seed: Uint8Array
) {
  const nativeResult = Libsodium.crypto_sign_seed_keypair(
    ...Array.from([pk, sk, seed], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_sign_seed_keypair execution failed: ${nativeResult}.`
    );
  }
  const resultBuf = new Uint8Array(nativeResult);
  pk.set(resultBuf.subarray(0, constants.crypto_sign_PUBLICKEYBYTES));
  sk.set(resultBuf.subarray(constants.crypto_sign_PUBLICKEYBYTES));
}

/**
 * Signs a message.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign
 */
export function crypto_sign(
  signedMessage: Uint8Array,
  message: Uint8Array,
  sk: Uint8Array
) {
  const nativeResult = Libsodium.crypto_sign(
    ...Array.from([signedMessage, message, sk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_sign execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  signedMessage.set(res);
}

/**
 * Verifies and opens a message.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_open
 */
export function crypto_sign_open(
  message: Uint8Array,
  signedMessage: Uint8Array,
  pk: Uint8Array
) {
  const nativeResult = Libsodium.crypto_sign_open(
    ...Array.from([message, signedMessage, pk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_sign_open execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  message.set(res);
}

/**
 * Signs a message but only stores the signature.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_detached
 */
export function crypto_sign_detached(
  signature: Uint8Array,
  message: Uint8Array,
  sk: Uint8Array
) {
  const nativeResult = Libsodium.crypto_sign_detached(
    ...Array.from([signature, message, sk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_sign_detached execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  signature.set(res);
}

/**
 * Verifies a signature.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_verify_detached
 */
export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: Uint8Array,
  pk: Uint8Array
) {
  const nativeResult = Libsodium.crypto_sign_verify_detached(
    ...Array.from([signature, message, pk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_sign_verify_detached execution failed: ${nativeResult}.`
    );
  }
  return true;
}

/**
 * Extracts an ed25519 public key from an ed25519 secret key.
 * https://sodium-friends.github.io/docs/docs/signing#crypto_sign_ed25519_sk_to_pk
 */
export function crypto_sign_ed25519_sk_to_pk(pk: Uint8Array, sk: Uint8Array) {
  const nativeResult = Libsodium.crypto_sign_ed25519_sk_to_pk(
    ...Array.from([pk, sk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_sign_ed25519_sk_to_pk execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  pk.set(res);
}
