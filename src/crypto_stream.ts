import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_stream_KEYBYTES = constants.crypto_stream_KEYBYTES;
export const crypto_stream_NONCEBYTES = constants.crypto_stream_NONCEBYTES;

/**
 * Encrypts, but not authenticates, a message based on a nonce and a key
 * https://sodium-friends.github.io/docs/docs/nonauthstreamingencryption#crypto_stream_xor
 */
export function crypto_stream_xor(
  cipherText: Uint8Array,
  message: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_stream_xor(
    ...Array.from([cipherText, message, nonce, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_stream_xor execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  cipherText.set(res);
}
