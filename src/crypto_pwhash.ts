import { Libsodium } from './libsodium';
import { mapArgs } from './helpers';
import { constants } from './constants';

export const crypto_pwhash_BYTES_MIN = constants.crypto_pwhash_BYTES_MIN;
export const crypto_pwhash_BYTES_MAX = constants.crypto_pwhash_BYTES_MAX;
export const crypto_pwhash_PASSWD_MIN = constants.crypto_pwhash_PASSWD_MIN;
export const crypto_pwhash_PASSWD_MAX = constants.crypto_pwhash_PASSWD_MAX;
export const crypto_pwhash_SALTBYTES = constants.crypto_pwhash_SALTBYTES;
export const crypto_pwhash_OPSLIMIT_MIN = constants.crypto_pwhash_OPSLIMIT_MIN;
export const crypto_pwhash_OPSLIMIT_MAX = constants.crypto_pwhash_OPSLIMIT_MAX;
export const crypto_pwhash_MEMLIMIT_MIN = constants.crypto_pwhash_MEMLIMIT_MIN;
export const crypto_pwhash_MEMLIMIT_MAX = constants.crypto_pwhash_MEMLIMIT_MAX;
export const crypto_pwhash_ALG_DEFAULT = constants.crypto_pwhash_ALG_DEFAULT;
export const crypto_pwhash_ALG_ARGON2I13 =
  constants.crypto_pwhash_ALG_ARGON2I13;
export const crypto_pwhash_ALG_ARGON2ID13 =
  constants.crypto_pwhash_ALG_ARGON2ID13;
export const crypto_pwhash_STRBYTES = constants.crypto_pwhash_STRBYTES;
export const crypto_pwhash_STRPREFIX = constants.crypto_pwhash_STRPREFIX;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE =
  constants.crypto_pwhash_OPSLIMIT_INTERACTIVE;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE =
  constants.crypto_pwhash_MEMLIMIT_INTERACTIVE;
export const crypto_pwhash_OPSLIMIT_MODERATE =
  constants.crypto_pwhash_OPSLIMIT_MODERATE;
export const crypto_pwhash_MEMLIMIT_MODERATE =
  constants.crypto_pwhash_MEMLIMIT_MODERATE;
export const crypto_pwhash_OPSLIMIT_SENSITIVE =
  constants.crypto_pwhash_OPSLIMIT_SENSITIVE;
export const crypto_pwhash_MEMLIMIT_SENSITIVE =
  constants.crypto_pwhash_MEMLIMIT_SENSITIVE;

/**
 * Creates a password hash.
 * https://sodium-friends.github.io/docs/docs/passwordhashing#crypto_pwhash
 */
export function crypto_pwhash(
  out: Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number,
  algorithm: number
) {
  const nativeResult = Libsodium.crypto_pwhash(
    ...Array.from([out, password, salt, opslimit, memlimit, algorithm], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_pwhash execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}

/**
 * Just like crypto_pwhash, but this will run password hashing on a separate worker, so it will not block the event loop.
 * https://sodium-friends.github.io/docs/docs/passwordhashing#crypto_pwhash_async
 */
// export function crypto_pwhash_async(
//   out: Uint8Array,
//   password: Uint8Array,
//   salt: Uint8Array,
//   opslimit: number,
//   memlimit: number,
//   algorithm: number,
//   callback: () => void
// ) {
//   const nativeResult = Libsodium.crypto_pwhash_async(
//     ...Array.from(
//       [out, password, salt, opslimit, memlimit, algorithm, callback],
//       mapArgs
//     )
//   );
//   const res = new Uint8Array(nativeResult);
//   out.set(res);
// }
