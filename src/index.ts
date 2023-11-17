import { NativeModules, Platform } from 'react-native';
import type { Constants } from './types';

const LINKING_ERROR =
  `The package 'sodium-react-native' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const Libsodium = NativeModules.SodiumReactNative
  ? NativeModules.SodiumReactNative
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

const constants: Constants = Libsodium.getConstants();

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

/**
 * Hashes a value with an optional key using the generichash method.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash
 */
export function crypto_generichash(
  out: Uint8Array,
  input: Uint8Array,
  key?: Uint8Array
) {
  if (!key) key = new Uint8Array(0);

  const nativeResult = Libsodium.crypto_generichash(
    ...Array.from([out, input, key], mapArgs)
  );
  const res = new Uint8Array(nativeResult);
  out.set(res);
}

/**
 * Same as crypto_generichash, except that this hashes an array of buffer's instead of a single one.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_batch
 */
export function crypto_generichash_batch(
  out: Uint8Array,
  batch: Uint8Array[],
  key?: Uint8Array
) {
  if (!key) key = new Uint8Array(0);

  const state = new Uint8Array(384);
  crypto_generichash_init(state, key, out.byteLength);
  batch.forEach((item) => crypto_generichash_update(state, item));
  crypto_generichash_final(state, out);
}

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

/**
 * Generates random scalar in ]0..L[ and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_scalar_random
 */
export function crypto_core_ed25519_scalar_random(random: Uint8Array) {
  const nativeResult = Libsodium.crypto_core_ed25519_scalar_random(
    Array.from(random)
  );
  const res = new Uint8Array(nativeResult);
  random.set(res);
}

/**
 * Adds point q to p and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_add
 */
export function crypto_core_ed25519_add(
  r: Uint8Array,
  p: Uint8Array,
  q: Uint8Array
) {
  const nativeResult = Libsodium.crypto_core_ed25519_add(
    ...Array.from([r, p, q], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_add execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  r.set(res);
}

/**
 * Subtracts point q to p and stores the result in r.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_sub
 */
export function crypto_core_ed25519_sub(
  r: Uint8Array,
  p: Uint8Array,
  q: Uint8Array
) {
  const nativeResult = Libsodium.crypto_core_ed25519_sub(
    ...Array.from([r, p, q], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_sub execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  r.set(res);
}

/**
 * Maps a crypto_core_ed25519_UNIFORMBYTES bytes vector (usually the output of a hash function) to a valid curve point and stores its compressed representation in p.
 * https://sodium-friends.github.io/docs/docs/finitefieldarithmetic#crypto_core_ed25519_from_uniform
 */
export function crypto_core_ed25519_from_uniform(p: Uint8Array, r: Uint8Array) {
  const nativeResult = Libsodium.crypto_core_ed25519_from_uniform(
    ...Array.from([p, r], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_core_ed25519_from_uniform execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  p.set(res);
}

/**
 * Hashes a value to a short hash based on a key.
 * https://sodium-friends.github.io/docs/docs/sha#crypto_hash_sha512
 */
export function crypto_hash_sha512(out: Uint8Array, input: Uint8Array) {
  const nativeResult = Libsodium.crypto_hash_sha512(
    ...Array.from([out, input], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`crypto_hash_sha512 execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}

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

/**
 * Initialise a new hash state with an optional key and the desired output length.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_init
 */
export function crypto_generichash_init(
  state: Uint8Array,
  key: Uint8Array,
  outlen: number
) {
  const nativeResult = Libsodium.crypto_generichash_init(
    ...Array.from([state, key, outlen], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_init execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  state.set(res);
}

/**
 * Update a hash state with a given input.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_update
 */
export function crypto_generichash_update(
  state: Uint8Array,
  input: Uint8Array
) {
  const nativeResult = Libsodium.crypto_generichash_update(
    ...Array.from([state, input], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_update execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  state.set(res);
}

/**
 * Finalize a given hash state and write the digest to output buffer.
 * https://sodium-friends.github.io/docs/docs/generichashing#crypto_generichash_final
 */
export function crypto_generichash_final(state: Uint8Array, out: Uint8Array) {
  const nativeResult = Libsodium.crypto_generichash_final(
    ...Array.from([state, out], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_generichash_final execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  out.set(res);
}

/**
 * Generates a new master key.
 * https://sodium-friends.github.io/docs/docs/keyderivation#crypto_kdf_keygen
 */
export function crypto_kdf_keygen(key: Uint8Array) {
  const nativeResult = Libsodium.crypto_kdf_keygen(Array.from(key));
  const res = new Uint8Array(nativeResult);
  key.set(res);
}

/**
 * Derives a new key from a master key.
 * https://sodium-friends.github.io/docs/docs/keyderivation#crypto_kdf_derive_from_key
 */
export function crypto_kdf_derive_from_key(
  subkey: Uint8Array,
  subkeyId: number,
  ctx: Uint8Array,
  key: Uint8Array
) {
  const nativeResult = Libsodium.crypto_kdf_derive_from_key(
    ...Array.from([subkey, subkeyId, ctx, key], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(
      `crypto_kdf_derive_from_key execution failed: ${nativeResult}.`
    );
  }
  const res = new Uint8Array(nativeResult);
  subkey.set(res);
}

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
  pk.set(res.subarray(0, constants.crypto_kx_PUBLICKEYBYTES));
  sk.set(res.subarray(constants.crypto_kx_PUBLICKEYBYTES));
}

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

/**
 * Fills buf with random data.
 * https://sodium-friends.github.io/docs/docs/generatingrandomdata#randombytes_buf
 */
export function randombytes_buf(arr: Uint8Array) {
  const nativeResult = Libsodium.randombytes_buf(Array.from(arr));
  const res = new Uint8Array(nativeResult);
  arr.set(res);
}

/**
 * Pads buf with random data from index unpaddedLength up to closest multiple of blocksize.
 * https://sodium-friends.github.io/docs/docs/padding#sodium_pad
 */
export function sodium_pad(
  buf: Uint8Array,
  unpaddedLength: number,
  blocksize: number
) {
  const nativeResult = Libsodium.sodium_pad(
    ...Array.from([buf, unpaddedLength, blocksize], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`sodium_pad execution failed: ${nativeResult}.`);
  }
  const res = new Uint8Array(nativeResult);
  buf.set(res);
  return nativeResult.length;
}

/**
 * Calculates unpaddedLength from a padded buf with blocksize.
 * https://sodium-friends.github.io/docs/docs/padding#sodium_unpad
 */
export function sodium_unpad(
  buf: Uint8Array,
  unpaddedLength: number,
  blocksize: number
) {
  const nativeResult = Libsodium.sodium_unpad(
    ...Array.from([buf, unpaddedLength, blocksize], mapArgs)
  );
  if (typeof nativeResult === 'string') {
    throw new Error(`sodium_unpad execution failed: ${nativeResult}.`);
  }
  return nativeResult;
}

/**
 * Compares a with b, in constant-time for a.length.
 * https://sodium-friends.github.io/docs/docs/helpers#sodium_memcmp
 */
export function sodium_memcmp(a: Uint8Array, b: Uint8Array) {
  return vn(a, 0, b, 0, a.byteLength) === 0 && a.byteLength === b.byteLength;
}

export function sodium_malloc(n: Uint8Array) {
  return new Uint8Array(n);
}

export function sodium_free(n: Uint8Array) {
  sodium_memzero(n);
}

export function sodium_memzero(arr: Uint8Array) {
  arr.fill(0);
}

function mapArgs(arg: number | Uint8Array | null) {
  if (arg === null) return [];
  if (typeof arg === 'number') return arg;
  return Array.from(arg);
}

// constant time compare
function vn(x: Uint8Array, xi: number, y: Uint8Array, yi: number, n: number) {
  let d = 0;
  for (let i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
  return (1 & ((d - 1) >>> 8)) - 1;
}

export const crypto_aead_xchacha20poly1305_ietf_ABYTES =
  Libsodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  Libsodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
  Libsodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NSECBYTES =
  Libsodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
export const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX =
  Libsodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
export const crypto_aead_chacha20poly1305_ietf_ABYTES =
  Libsodium.crypto_aead_chacha20poly1305_ietf_ABYTES;
export const crypto_aead_chacha20poly1305_ietf_KEYBYTES =
  Libsodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES =
  Libsodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
export const crypto_aead_chacha20poly1305_ietf_NSECBYTES =
  Libsodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES;
export const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
  Libsodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
export const crypto_core_ed25519_SCALARBYTES =
  Libsodium.crypto_core_ed25519_SCALARBYTES;
export const crypto_core_ed25519_BYTES = Libsodium.crypto_core_ed25519_BYTES;
export const crypto_core_ed25519_UNIFORMBYTES =
  Libsodium.crypto_core_ed25519_UNIFORMBYTES;
export const crypto_hash_sha512_BYTES = Libsodium.crypto_hash_sha512_BYTES;
export const crypto_secretbox_KEYBYTES = Libsodium.crypto_secretbox_KEYBYTES;
export const crypto_secretbox_MACBYTES = Libsodium.crypto_secretbox_MACBYTES;
export const crypto_secretbox_NONCEBYTES =
  Libsodium.crypto_secretbox_NONCEBYTES;
export const crypto_pwhash_BYTES_MIN = Libsodium.crypto_pwhash_BYTES_MIN;
export const crypto_pwhash_BYTES_MAX = Libsodium.crypto_pwhash_BYTES_MAX;
export const crypto_pwhash_PASSWD_MIN = Libsodium.crypto_pwhash_PASSWD_MIN;
export const crypto_pwhash_PASSWD_MAX = Libsodium.crypto_pwhash_PASSWD_MAX;
export const crypto_pwhash_SALTBYTES = Libsodium.crypto_pwhash_SALTBYTES;
export const crypto_pwhash_OPSLIMIT_MIN = Libsodium.crypto_pwhash_OPSLIMIT_MIN;
export const crypto_pwhash_OPSLIMIT_MAX = Libsodium.crypto_pwhash_OPSLIMIT_MAX;
export const crypto_pwhash_MEMLIMIT_MIN = Libsodium.crypto_pwhash_MEMLIMIT_MIN;
export const crypto_pwhash_MEMLIMIT_MAX = Libsodium.crypto_pwhash_MEMLIMIT_MAX;
export const crypto_pwhash_ALG_DEFAULT = Libsodium.crypto_pwhash_ALG_DEFAULT;
export const crypto_pwhash_ALG_ARGON2I13 =
  Libsodium.crypto_pwhash_ALG_ARGON2I13;
export const crypto_pwhash_ALG_ARGON2ID13 =
  Libsodium.crypto_pwhash_ALG_ARGON2ID13;
export const crypto_pwhash_STRBYTES = Libsodium.crypto_pwhash_STRBYTES;
export const crypto_pwhash_STRPREFIX = Libsodium.crypto_pwhash_STRPREFIX;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE =
  Libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE =
  Libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
export const crypto_pwhash_OPSLIMIT_MODERATE =
  Libsodium.crypto_pwhash_OPSLIMIT_MODERATE;
export const crypto_pwhash_MEMLIMIT_MODERATE =
  Libsodium.crypto_pwhash_MEMLIMIT_MODERATE;
export const crypto_pwhash_OPSLIMIT_SENSITIVE =
  Libsodium.crypto_pwhash_OPSLIMIT_SENSITIVE;
export const crypto_pwhash_MEMLIMIT_SENSITIVE =
  Libsodium.crypto_pwhash_MEMLIMIT_SENSITIVE;
export const crypto_sign_BYTES = Libsodium.crypto_sign_BYTES;
export const crypto_sign_SEEDBYTES = Libsodium.crypto_sign_SEEDBYTES;
export const crypto_sign_PUBLICKEYBYTES = Libsodium.crypto_sign_PUBLICKEYBYTES;
export const crypto_sign_SECRETKEYBYTES = Libsodium.crypto_sign_SECRETKEYBYTES;
export const crypto_scalarmult_ed25519_BYTES =
  Libsodium.crypto_scalarmult_ed25519_BYTES;
export const crypto_scalarmult_ed25519_SCALARBYTES =
  Libsodium.crypto_scalarmult_ed25519_SCALARBYTES;
export const crypto_scalarmult_BYTES = Libsodium.crypto_scalarmult_BYTES;
export const crypto_scalarmult_SCALARBYTES =
  Libsodium.crypto_scalarmult_SCALARBYTES;
export const crypto_generichash_STATEBYTES =
  Libsodium.crypto_generichash_STATEBYTES;
export const crypto_generichash_KEYBYTES =
  Libsodium.crypto_generichash_KEYBYTES;
export const crypto_generichash_KEYBYTES_MIN =
  Libsodium.crypto_generichash_KEYBYTES_MIN;
export const crypto_generichash_KEYBYTES_MAX =
  Libsodium.crypto_generichash_KEYBYTES_MAX;
export const crypto_generichash_BYTES = Libsodium.crypto_generichash_BYTES;
export const crypto_generichash_BYTES_MIN =
  Libsodium.crypto_generichash_BYTES_MIN;
export const crypto_generichash_BYTES_MAX =
  Libsodium.crypto_generichash_BYTES_MAX;
export const crypto_kdf_KEYBYTES = Libsodium.crypto_kdf_KEYBYTES;
export const crypto_kdf_BYTES_MIN = Libsodium.crypto_kdf_BYTES_MIN;
export const crypto_kdf_BYTES_MAX = Libsodium.crypto_kdf_BYTES_MAX;
export const crypto_kdf_CONTEXTBYTES = Libsodium.crypto_kdf_CONTEXTBYTES;
export const crypto_stream_KEYBYTES = Libsodium.crypto_stream_KEYBYTES;
export const crypto_stream_NONCEBYTES = Libsodium.crypto_stream_NONCEBYTES;
export const crypto_secretstream_xchacha20poly1305_STATEBYTES =
  Libsodium.crypto_secretstream_xchacha20poly1305_STATEBYTES;
export const crypto_secretstream_xchacha20poly1305_ABYTES =
  Libsodium.crypto_secretstream_xchacha20poly1305_ABYTES;
export const crypto_secretstream_xchacha20poly1305_HEADERBYTES =
  Libsodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
export const crypto_secretstream_xchacha20poly1305_KEYBYTES =
  Libsodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;
export const crypto_secretstream_xchacha20poly1305_TAGBYTES =
  Libsodium.crypto_secretstream_xchacha20poly1305_TAGBYTES;
export const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
  Libsodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
export const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
  Libsodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
export const crypto_secretstream_xchacha20poly1305_TAG_PUSH =
  Libsodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH;
export const crypto_secretstream_xchacha20poly1305_TAG_REKEY =
  Libsodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY;
export const crypto_secretstream_xchacha20poly1305_TAG_FINAL =
  Libsodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
export const crypto_kx_PUBLICKEYBYTES = Libsodium.crypto_kx_PUBLICKEYBYTES;
export const crypto_kx_SECRETKEYBYTES = Libsodium.crypto_kx_SECRETKEYBYTES;

const SodiumAPI = {
  ...constants,
  crypto_aead_chacha20poly1305_ietf_keygen,
  crypto_aead_chacha20poly1305_ietf_encrypt,
  crypto_aead_chacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_core_ed25519_scalar_random,
  crypto_core_ed25519_add,
  crypto_core_ed25519_sub,
  crypto_core_ed25519_from_uniform,
  crypto_generichash_init,
  crypto_generichash_update,
  crypto_generichash_final,
  crypto_generichash_batch,
  crypto_generichash,
  crypto_hash_sha512,
  crypto_kdf_keygen,
  crypto_kdf_derive_from_key,
  crypto_kx_keypair,
  crypto_onetimeauth,
  crypto_pwhash,
  // crypto_pwhash_async,
  crypto_scalarmult,
  crypto_scalarmult_base,
  crypto_scalarmult_ed25519,
  crypto_scalarmult_ed25519_noclamp,
  crypto_scalarmult_ed25519_base,
  crypto_scalarmult_ed25519_base_noclamp,
  crypto_sign_keypair,
  crypto_sign_seed_keypair,
  crypto_sign,
  crypto_sign_open,
  crypto_sign_detached,
  crypto_sign_verify_detached,
  crypto_sign_ed25519_sk_to_pk,
  crypto_stream_xor,
  crypto_secretstream_xchacha20poly1305_keygen,
  crypto_secretstream_xchacha20poly1305_init_push,
  crypto_secretstream_xchacha20poly1305_push,
  crypto_secretstream_xchacha20poly1305_init_pull,
  crypto_secretstream_xchacha20poly1305_pull,
  crypto_secretbox_easy,
  crypto_secretbox_open_easy,
  randombytes_buf,
  sodium_free,
  sodium_pad,
  sodium_unpad,
  sodium_malloc,
  sodium_memcmp,
  sodium_memzero,
};

export default SodiumAPI;
