import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_secretbox_BOXZEROBYTES =
  constants.crypto_secretbox_BOXZEROBYTES;
export const crypto_secretbox_KEYBYTES = constants.crypto_secretbox_KEYBYTES;
export const crypto_secretbox_MACBYTES = constants.crypto_secretbox_MACBYTES;
export const crypto_secretbox_NONCEBYTES =
  constants.crypto_secretbox_NONCEBYTES;
export const crypto_secretbox_ZEROBYTES = constants.crypto_secretbox_ZEROBYTES;

/**
 * Encrypts a message with a key and a nonce.
 * https://sodium-friends.github.io/docs/docs/secretkeyboxencryption#crypto_secretbox_easy
 */
export function crypto_secretbox_easy(
  cipherText: Uint8Array,
  message: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_secretbox_easy(
    ...Array.from([cipherText, message, nonce, key], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  cipherText.set(res);
}

/**
 * Decrypts a message encoded with the easy method
 * https://sodium-friends.github.io/docs/docs/secretkeyboxencryption#crypto_secretbox_open_easy
 */
export function crypto_secretbox_open_easy(
  message: Uint8Array,
  cipherText: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_secretbox_open_easy(
    ...Array.from([message, cipherText, nonce, key], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  message.set(res);
}
