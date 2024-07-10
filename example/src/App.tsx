import * as React from 'react';
import { StyleSheet, View, SafeAreaView } from 'react-native';
import sodium from 'sodium-react-native-direct';
import b4a from 'b4a';

import Text from './components/Text';
import Button from './components/Button';
import { sleep } from './helpers';

import Tests from './Tests';

export default function App() {
  const [result, setResult] = React.useState('');
  const [showTests, setShowTests] = React.useState(false);

  const onCryptoGenericHash = () => {
    const out = new Uint8Array(sodium.crypto_generichash_BYTES);
    const input = b4a.from('Hello, World!');
    const key = new Uint8Array(sodium.crypto_generichash_KEYBYTES);

    sodium.randombytes_buf(key); // insert random data into key
    sodium.crypto_generichash(out, input, key);

    const decoded = b4a.toString(out, 'hex');
    setResult(decoded);
  };

  const onCryptoGenericHashBatch = () => {
    const out = new Uint8Array(sodium.crypto_generichash_BYTES);
    const input = b4a.from('Hello, World!');
    const inArray = [];
    for (var i = 0; i < 10; i++) inArray.push(input);

    const key = new Uint8Array(sodium.crypto_generichash_KEYBYTES);

    sodium.randombytes_buf(key); // insert random data into key
    sodium.crypto_generichash_batch(out, inArray, key);

    const decoded = b4a.toString(out, 'hex');
    setResult(decoded);
  };

  const onCryptoHashSha512 = () => {
    const out = new Uint8Array(sodium.crypto_hash_sha512_BYTES);
    const message = b4a.from('Hello, World!');

    sodium.crypto_hash_sha512(out, message);

    const decoded = b4a.toString(out, 'hex');
    setResult(decoded);
  };

  const onCryptoPwhash = () => {
    const out = new Uint8Array(sodium.crypto_pwhash_BYTES_MIN);
    const password = b4a.from('hunter2');
    const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_MIN;
    const algorithm = sodium.crypto_pwhash_ALG_DEFAULT;

    sodium.crypto_pwhash(out, password, salt, opslimit, memlimit, algorithm);

    const decoded = b4a.toString(out, 'hex');
    setResult(decoded);
  };

  const onCryptoAeadChacha20poly1305Ietf = async () => {
    // Encrypt
    const message = b4a.from('Hello, World!');
    const cipherText = new Uint8Array(
      message.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
    );
    const npub = new Uint8Array(
      sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    );
    const key = new Uint8Array(
      sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES
    );

    sodium.randombytes_buf(npub); // insert random data into npub
    sodium.randombytes_buf(key); // insert random data into key

    try {
      sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
        cipherText,
        message,
        null,
        null,
        npub,
        key
      );
      const encrypted = b4a.toString(cipherText, 'hex');
      setResult(`Encrypted: ${encrypted}\nDecrypting in 2 seconds...`);

      await sleep(2000);

      // Decrypt
      const decrypted = new Uint8Array(
        cipherText.byteLength - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
      );

      sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted,
        null,
        cipherText,
        null,
        npub,
        key
      );
      const decrupted = b4a.toString(decrypted);
      setResult(`Decrypted: ${decrupted}`);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoSecretboxEasy = async () => {
    // Encrypt
    const message = b4a.from('Hello, World!');
    const cipherText = new Uint8Array(
      message.byteLength + sodium.crypto_secretbox_MACBYTES
    );
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    const key = new Uint8Array(sodium.crypto_secretbox_KEYBYTES);

    sodium.randombytes_buf(nonce); // insert random data into nonce
    sodium.randombytes_buf(key); // insert random data into key

    try {
      sodium.crypto_secretbox_easy(cipherText, message, nonce, key);
      const encrypted = b4a.toString(cipherText, 'hex');
      setResult(`Encrypted: ${encrypted}\nDecrypting in 2 seconds...`);

      await sleep(2000);

      // Decrypt
      const decrypted_buf = new Uint8Array(
        cipherText.byteLength - sodium.crypto_secretbox_MACBYTES
      );

      sodium.crypto_secretbox_open_easy(decrypted_buf, cipherText, nonce, key);
      const decrypted = b4a.toString(decrypted_buf);
      setResult(`Decrypted: ${decrypted}`);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoStreamXor = async () => {
    // Encrypt
    const message = b4a.from('Hello, World!');
    const cipherText = new Uint8Array(message.byteLength);
    const nonce = new Uint8Array(sodium.crypto_stream_NONCEBYTES);
    const key = new Uint8Array(sodium.crypto_stream_KEYBYTES);

    sodium.randombytes_buf(nonce); // insert random data into nonce
    sodium.randombytes_buf(key); // insert random data into key

    try {
      sodium.crypto_stream_xor(cipherText, message, nonce, key);
      const encrypted = b4a.toString(cipherText, 'hex');
      setResult(`Encrypted: ${encrypted}\nDecrypting in 2 seconds...`);

      await sleep(2000);

      // Decrypt
      sodium.crypto_stream_xor(message, cipherText, nonce, key);
      const decrypted = b4a.toString(message);
      setResult(`Decrypted: ${decrypted}`);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoSign = () => {
    const message = b4a.from('Hello, World!');
    const pk = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
    const sk = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);

    sodium.crypto_sign_keypair(pk, sk);

    console.log({ pk: b4a.toString(pk, 'hex') });
    console.log({ sk: b4a.toString(sk, 'hex') });

    const signedMessage = new Uint8Array(
      sodium.crypto_sign_BYTES + message.byteLength
    );
    sodium.crypto_sign(signedMessage, message, sk);

    try {
      sodium.crypto_sign_open(message, signedMessage, pk);
      const decoded = b4a.toString(message);
      setResult(`Signed and verified: ${decoded}`);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoSignDetached = () => {
    const message = b4a.from('Hello, World!');
    const pk = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
    const sk = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);

    sodium.crypto_sign_keypair(pk, sk);

    console.log({ pk: b4a.toString(pk, 'hex') });
    console.log({ sk: b4a.toString(sk, 'hex') });

    const signature = new Uint8Array(sodium.crypto_sign_BYTES);
    sodium.crypto_sign_detached(signature, message, sk);

    try {
      sodium.crypto_sign_verify_detached(signature, message, pk);
      setResult('Signed and verified.');
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoSignSeedKeypair = () => {
    const pk = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
    const sk = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);
    const seed = new Uint8Array(sodium.crypto_sign_SEEDBYTES);

    try {
      sodium.crypto_sign_seed_keypair(pk, sk, seed);

      const pkDecoded = b4a.toString(pk, 'hex');
      const skDecoded = b4a.toString(sk, 'hex');

      console.log({ pk: pkDecoded });
      console.log({ sk: skDecoded });

      setResult(pkDecoded);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onCryptoSignEd25519SkToPk = () => {
    const pk = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
    const sk = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);

    sodium.randombytes_buf(sk); // insert random data into secret key

    try {
      sodium.crypto_sign_ed25519_sk_to_pk(pk, sk);

      const pkDecoded = b4a.toString(pk, 'hex');
      const skDecoded = b4a.toString(sk, 'hex');

      console.log({ pk: pkDecoded });
      console.log({ sk: skDecoded });

      setResult(pkDecoded);
    } catch (error: any) {
      setResult(error.message);
    }
  };

  const onRandomBytesBuf = () => {
    const buffer = new Uint8Array(16);

    sodium.randombytes_buf(buffer);

    const decoded = b4a.toString(buffer, 'hex');
    setResult(decoded);
  };

  const onCryptoBoxSeal = async () => {
    const message = b4a.from('Hello, World!');
    const cipherText = new Uint8Array(
      message.byteLength + sodium.crypto_box_SEALBYTES
    );
    const pk = new Uint8Array(sodium.crypto_box_PUBLICKEYBYTES);
    const sk = new Uint8Array(sodium.crypto_box_SECRETKEYBYTES);

    try {
      sodium.crypto_box_keypair(pk, sk);
      console.log({ pk: b4a.toString(pk, 'hex') });
      console.log({ sk: b4a.toString(sk, 'hex') });
      sodium.crypto_box_seal(cipherText, message, pk);
      const encrypted = b4a.toString(cipherText, 'hex');
      console.log({ encrypted });
      setResult(`Encrypted: ${encrypted}\nDecrypting in 2 seconds...`);
      await sleep(2000);

      const decrypted = new Uint8Array(
        cipherText.byteLength - sodium.crypto_box_SEALBYTES
      );
      sodium.crypto_box_seal_open(decrypted, cipherText, pk, sk);
      const decoded = b4a.toString(decrypted);
      console.log({ decoded });
      setResult(`Decrypted: ${decoded}`);
    } catch (error: any) {
      console.log(error);
      setResult(error.message);
    }
  };

  const openTests = () => {
    setShowTests(true);
  };

  if (showTests) {
    return <Tests />;
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.buttons}>
        <Button
          style={styles.button}
          title="CryptoGenericHash"
          onPress={onCryptoGenericHash}
        />
        <Button
          style={styles.button}
          title="CryptoGenericHashBatch"
          onPress={onCryptoGenericHashBatch}
        />
        <Button
          style={styles.button}
          title="CryptoHashSha512"
          onPress={onCryptoHashSha512}
        />
        <Button
          style={styles.button}
          title="CryptoPwhash"
          onPress={onCryptoPwhash}
        />
        <Button
          style={styles.button}
          title="CryptoAeadChacha20poly1305Ietf"
          onPress={onCryptoAeadChacha20poly1305Ietf}
        />
        <Button
          style={styles.button}
          title="CryptoSecretboxEasy"
          onPress={onCryptoSecretboxEasy}
        />
        <Button
          style={styles.button}
          title="CryptoStreamXor"
          onPress={onCryptoStreamXor}
        />
        <Button
          style={styles.button}
          title="CryptoSign"
          onPress={onCryptoSign}
        />
        <Button
          style={styles.button}
          title="CryptoSignDetached"
          onPress={onCryptoSignDetached}
        />
        <Button
          style={styles.button}
          title="CryptoSignSeedKeypair"
          onPress={onCryptoSignSeedKeypair}
        />
        <Button
          style={styles.button}
          title="CryptoSignEd25519SkToPk"
          onPress={onCryptoSignEd25519SkToPk}
        />
        <Button
          style={styles.button}
          title="RandomBytesBuf"
          onPress={onRandomBytesBuf}
        />
        <Button
          style={styles.button}
          title="CryptoBoxSeal"
          onPress={onCryptoBoxSeal}
        />
        <Button style={styles.button} title="Open tests" onPress={openTests} />
      </View>

      {result && (
        <View style={styles.result}>
          <Text style={styles.resultTitle}>Result:</Text>
          <Text>{result}</Text>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    paddingVertical: 16,
    flex: 1,
  },
  buttons: {
    alignItems: 'center',
  },
  button: {
    marginBottom: 16,
  },
  result: {
    marginTop: 'auto',
    paddingHorizontal: 16,
  },
  resultTitle: {
    fontSize: 18,
  },
});
