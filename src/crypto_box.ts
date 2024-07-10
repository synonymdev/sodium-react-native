import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_box_PUBLICKEYBYTES = constants.crypto_box_PUBLICKEYBYTES;
export const crypto_box_SECRETKEYBYTES = constants.crypto_box_SECRETKEYBYTES;
export const crypto_box_SEEDBYTES = constants.crypto_box_SEEDBYTES;
export const crypto_box_NONCEBYTES = constants.crypto_box_NONCEBYTES;
export const crypto_box_MACBYTES = constants.crypto_box_MACBYTES;
export const crypto_box_SEALBYTES = constants.crypto_box_SEALBYTES;

/**
 * Encrypts a message with the recipient's public key.
 * https://sodium-friends.github.io/docs/docs/keyboxencryption#crypto_box_keypair
 */
export function crypto_box_keypair(pk: Uint8Array, sk: Uint8Array) {
  const nativeResult = Libsodium.crypto_box_keypair(
    ...Array.from([pk, sk], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  pk.set(res.subarray(0, crypto_box_PUBLICKEYBYTES));
  sk.set(res.subarray(crypto_box_PUBLICKEYBYTES));
}

/**
 * Keypairs can be generated with crypto_box_keypair() or crypto_box_seed_keypair().
 * https://sodium-friends.github.io/docs/docs/sealedboxencryption#crypto_box_seal
 */
export function crypto_box_seal(
  cipherText: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
) {
  const nativeResult = Libsodium.crypto_box_seal(
    ...Array.from([cipherText, message, publicKey], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  cipherText.set(res);
}

/**
 * Decrypts a message encoded with the sealed box method.
 * https://sodium-friends.github.io/docs/docs/sealedboxencryption#crypto_box_seal_open
 */
export function crypto_box_seal_open(
  message: Uint8Array,
  cipherText: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array
) {
  const nativeResult = Libsodium.crypto_box_seal_open(
    ...Array.from([message, cipherText, publicKey, privateKey], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  message.set(res);
}
