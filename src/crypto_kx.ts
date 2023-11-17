import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_kx_PUBLICKEYBYTES = constants.crypto_kx_PUBLICKEYBYTES;
export const crypto_kx_SECRETKEYBYTES = constants.crypto_kx_SECRETKEYBYTES;
export const crypto_kx_SEEDBYTES = constants.crypto_kx_SEEDBYTES;

/**
 * Creates a key exchange key pair.
 * https://sodium-friends.github.io/docs/docs/keyexchange#crypto_kx_keypair
 */
export function crypto_kx_keypair(pk: Uint8Array, sk: Uint8Array) {
  const nativeResult = Libsodium.crypto_kx_keypair(
    ...Array.from([pk, sk], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_kx_keypair execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  pk.set(res.subarray(0, Libsodium.crypto_kx_PUBLICKEYBYTES));
  sk.set(res.subarray(Libsodium.crypto_kx_PUBLICKEYBYTES));
}

/**
 * Creates a key exchange key pair based on a seed.
 * https://sodium-friends.github.io/docs/docs/keyexchange#crypto_kx_seed_keypair
 */
export function crypto_kx_seed_keypair(
  pk: Uint8Array,
  sk: Uint8Array,
  seed: Uint8Array
) {
  const nativeResult = Libsodium.crypto_kx_seed_keypair(
    ...Array.from([pk, sk, seed], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_kx_seed_keypair execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  pk.set(res.subarray(0, Libsodium.crypto_kx_PUBLICKEYBYTES));
  sk.set(res.subarray(Libsodium.crypto_kx_PUBLICKEYBYTES));
}
