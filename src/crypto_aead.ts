import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_aead_xchacha20poly1305_ietf_ABYTES =
  constants.crypto_aead_xchacha20poly1305_ietf_ABYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  constants.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
  constants.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NSECBYTES =
  constants.crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
export const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX =
  constants.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
export const crypto_aead_chacha20poly1305_ietf_ABYTES =
  constants.crypto_aead_chacha20poly1305_ietf_ABYTES;
export const crypto_aead_chacha20poly1305_ietf_KEYBYTES =
  constants.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES =
  constants.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
export const crypto_aead_chacha20poly1305_ietf_NSECBYTES =
  constants.crypto_aead_chacha20poly1305_ietf_NSECBYTES;
export const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
  constants.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;

/**
 * Generates a new encryption k.
 * https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_keygen
 */
export function crypto_aead_xchacha20poly1305_ietf_keygen(key: Uint8Array) {
  const nativeResult = Libsodium.crypto_aead_xchacha20poly1305_ietf_keygen(
    Array.from(key)
  );
  const res = new Uint8Array(nativeResult);
  key.set(res);
}

/**
 * Encrypts a message with npub, key and optional additional data.
 * https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_encrypt
 */
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  cipherText: Uint8Array,
  message: Uint8Array,
  add_data: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ...Array.from([cipherText, message, add_data, nsec, npub, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_aead_xchacha20poly1305_ietf_encrypt execeution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  cipherText.set(res);
  return res.byteLength;
}

/**
 * Decrypts a message with npub, key and optional additional data.
 * https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_decrypt
 */
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  message: Uint8Array,
  nsec: null,
  cipherText: Uint8Array,
  add_data: Uint8Array | null,
  npub: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    ...Array.from([message, nsec, cipherText, add_data, npub, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_aead_xchacha20poly1305_ietf_decrypt execeution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  message.set(res);
  return res.byteLength;
}

/**
 * Generates a new encryption k.
 */
export function crypto_aead_chacha20poly1305_ietf_keygen(key: Uint8Array) {
  const nativeResult = Libsodium.crypto_aead_chacha20poly1305_ietf_keygen(
    Array.from(key)
  );
  const res = new Uint8Array(nativeResult);
  key.set(res);
}

/**
 * Encrypts a message with npub, key and optional additional data.
 * https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_encrypt
 */
export function crypto_aead_chacha20poly1305_ietf_encrypt(
  cipherText: Uint8Array,
  message: Uint8Array,
  add_data: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    ...Array.from([cipherText, message, add_data, nsec, npub, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_aead_chacha20poly1305_ietf_encrypt execeution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  cipherText.set(res);
  return res.byteLength;
}

/**
 * Decrypts a message with npub, key and optional additional data.
 * https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_decrypt
 */
export function crypto_aead_chacha20poly1305_ietf_decrypt(
  message: Uint8Array,
  nsec: null,
  cipherText: Uint8Array,
  add_data: Uint8Array | null,
  npub: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    ...Array.from([message, nsec, cipherText, add_data, npub, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_aead_chacha20poly1305_ietf_decrypt execeution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  message.set(res);
  return res.byteLength;
}
