import * as constants from './constants';
import * as crypto_aead from './crypto_aead';
// import * as crypto_auth from './crypto_auth';
// import * as crypto_box from './crypto_box';
import * as crypto_core from './crypto_core';
import * as crypto_generichash from './crypto_generichash';
import * as crypto_hash from './crypto_hash';
// import * as crypto_hash_sha256 from './crypto_hash_sha256';
import * as crypto_kdf from './crypto_kdf';
import * as crypto_kx from './crypto_kx';
import * as crypto_onetimeauth from './crypto_onetimeauth';
import * as crypto_pwhash from './crypto_pwhash';
import * as crypto_scalarmult from './crypto_scalarmult';
import * as crypto_secretbox from './crypto_secretbox';
import * as crypto_secretstream from './crypto_secretstream';
// import * as crypto_shorthash from './crypto_shorthash';
import * as crypto_sign from './crypto_sign';
import * as crypto_stream from './crypto_stream';
// import * as crypto_stream_chacha20 from './crypto_stream_chacha20';
import * as crypto_verify from './crypto_verify';
import * as memory from './memory';
import * as padding from './padding';
import * as randombytes from './randombytes';

const sodium = {
  ...constants,
  ...crypto_aead,
  // ...crypto_auth,
  // ...crypto_box,
  ...crypto_core,
  ...crypto_generichash,
  ...crypto_hash,
  // ...crypto_hash_sha256,
  ...crypto_kdf,
  ...crypto_kx,
  ...crypto_onetimeauth,
  ...crypto_pwhash,
  ...crypto_scalarmult,
  ...crypto_secretbox,
  ...crypto_secretstream,
  // ...crypto_shorthash,
  ...crypto_sign,
  ...crypto_stream,
  // ...crypto_stream_chacha20,
  ...crypto_verify,
  ...padding,
  ...memory,
  ...randombytes,
};

module.exports = sodium;
export default sodium;
