import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_secretstream_xchacha20poly1305_STATEBYTES =
  constants.crypto_secretstream_xchacha20poly1305_STATEBYTES;
export const crypto_secretstream_xchacha20poly1305_ABYTES =
  constants.crypto_secretstream_xchacha20poly1305_ABYTES;
export const crypto_secretstream_xchacha20poly1305_HEADERBYTES =
  constants.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
export const crypto_secretstream_xchacha20poly1305_KEYBYTES =
  constants.crypto_secretstream_xchacha20poly1305_KEYBYTES;
export const crypto_secretstream_xchacha20poly1305_TAGBYTES =
  constants.crypto_secretstream_xchacha20poly1305_TAGBYTES;
export const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
  constants.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
export const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
  constants.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
export const crypto_secretstream_xchacha20poly1305_TAG_PUSH =
  constants.crypto_secretstream_xchacha20poly1305_TAG_PUSH;
export const crypto_secretstream_xchacha20poly1305_TAG_REKEY =
  constants.crypto_secretstream_xchacha20poly1305_TAG_REKEY;
export const crypto_secretstream_xchacha20poly1305_TAG_FINAL =
  constants.crypto_secretstream_xchacha20poly1305_TAG_FINAL;

/**
 * Generates a new encryption key.
 * https://sodium-friends.github.io/docs/docs/streamencryption#crypto_secretstream_xchacha20poly1305_keygen
 */
export function crypto_secretstream_xchacha20poly1305_keygen(key: Uint8Array) {
  const nativeResult = Libsodium.crypto_secretstream_xchacha20poly1305_keygen(
    Array.from(key)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_secretstream_xchacha20poly1305_keygen execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  key.set(res);
}

/**
 * Initializes state from the writer side with message header and encryption key. The header must be sent or stored with the stream. The key must be exchanged securely with the receiving / reading side.
 * https://sodium-friends.github.io/docs/docs/streamencryption#crypto_secretstream_xchacha20poly1305_init_push
 */
export function crypto_secretstream_xchacha20poly1305_init_push(
  state: Uint8Array,
  header: Uint8Array,
  key: Uint8Array
) {
  const nativeResult =
    Libsodium.crypto_secretstream_xchacha20poly1305_init_push(
      ...Array.from([state, header, key], mapArgs)
    );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_secretstream_xchacha20poly1305_init_push execution failed: ${nativeResult}.`
    );
  }
  const resultBuf = new Uint8Array(nativeResult);
  state.set(
    resultBuf.subarray(
      0,
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES
    )
  );
  header.set(
    resultBuf.subarray(
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES
    )
  );
}

/**
 * Encrypts a message with a certain tag and optional additional data.
 * https://sodium-friends.github.io/docs/docs/streamencryption#crypto_secretstream_xchacha20poly1305_push
 */
export function crypto_secretstream_xchacha20poly1305_push(
  state: Uint8Array,
  cipherText: Uint8Array,
  message: Uint8Array,
  add_data: Uint8Array | null,
  tag: Uint8Array
) {
  const nativeResult = Libsodium.crypto_secretstream_xchacha20poly1305_push(
    ...Array.from([state, cipherText, message, add_data, tag], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_secretstream_xchacha20poly1305_push execution failed: ${nativeResult}.`
    );
  }
  const resultBuf = new Uint8Array(nativeResult);
  state.set(
    resultBuf.subarray(
      0,
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES
    )
  );
  cipherText.set(
    resultBuf.subarray(
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES
    )
  );
}

/**
 * Initializes state from the reader side with message header and encryption key. The header must be retrieved from somewhere. The key must be exchanged securely with the sending / writing side.
 * https://sodium-friends.github.io/docs/docs/streamencryption#crypto_secretstream_xchacha20poly1305_init_pull
 */
export function crypto_secretstream_xchacha20poly1305_init_pull(
  state: Uint8Array,
  header: Uint8Array,
  key: Uint8Array
) {
  const nativeResult =
    Libsodium.crypto_secretstream_xchacha20poly1305_init_pull(
      ...Array.from([state, header, key], mapArgs)
    );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_secretstream_xchacha20poly1305_init_pull execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  state.set(res);
}

/**
 * Decrypts a message with optional additional data ad, and writes message tag to tag. Make sure to check this!
 * https://sodium-friends.github.io/docs/docs/streamencryption#crypto_secretstream_xchacha20poly1305_pull
 */
export function crypto_secretstream_xchacha20poly1305_pull(
  state: Uint8Array,
  message: Uint8Array,
  tag: Uint8Array,
  cipherText: Uint8Array,
  add_data: Uint8Array | null
) {
  const nativeResult = Libsodium.crypto_secretstream_xchacha20poly1305_pull(
    ...Array.from([state, message, tag, cipherText, add_data], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_secretstream_xchacha20poly1305_pull execution failed: ${nativeResult}.`
    );
  }
  const resultBuf = new Uint8Array(nativeResult);
  state.set(
    resultBuf.subarray(
      0,
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES
    )
  );
  tag[0] =
    resultBuf[constants.crypto_secretstream_xchacha20poly1305_STATEBYTES];
  message.set(
    resultBuf.subarray(
      constants.crypto_secretstream_xchacha20poly1305_STATEBYTES + 1
    )
  );
}
