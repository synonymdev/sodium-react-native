import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_onetimeauth_BYTES = constants.crypto_onetimeauth_BYTES;
export const crypto_onetimeauth_KEYBYTES =
  constants.crypto_onetimeauth_KEYBYTES;

/**
 * Creates an authentication token based on a onetime key.
 * https://sodium-friends.github.io/docs/docs/onetimeauthentication#crypto_onetimeauth
 */
export function crypto_onetimeauth(
  out: Uint8Array,
  input: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_onetimeauth(
    ...Array.from([out, input, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_onetimeauth execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}
