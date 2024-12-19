const bitcoinjs = require('bitcoinjs-lib');
const crypto = require('crypto');

function private_key_to_public_key(privKeyHex) {
  const privateKey = bitcoinjs.ECPair.fromPrivateKey(Buffer.from(privKeyHex, 'hex'));
  return privateKey.getPublicKey().encodeCompressed('hex');
}

function pubkey_to_address(pubKey, magicByte = 0) {
  const pubKeyBuffer = Buffer.from(pubKey, 'hex');
  const sha256 = crypto.createHash('sha256');
  const ripemd160 = crypto.createHash('ripemd160');
  sha256.update(pubKeyBuffer);
  ripemd160.update(sha256.digest());
  const address = bitcoinjs.base58check.encode(Buffer.concat([Buffer.from([magicByte]), ripemd160.digest()]));
  return address;
}

// Replace '' as private key
const privateKeyWIF = '';
const privateKeyHex = bitcoinjs.base58check.decode(privateKeyWIF).toString('hex').slice(2); // Decode WIF and remove '80' prefix
console.log("Private key (hex):", privateKeyHex);

const publicKey = private_key_to_public_key(privateKeyHex);
console.log("Public key (hex compressed):", publicKey);

const address = pubkey_to_address(publicKey);
console.log("Compressed Bitcoin address (base58check):", address);