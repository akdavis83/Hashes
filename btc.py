import bitcoin, hashlib, binascii, base58

def private_key_to_public_key(privKeyHex: str) -> (int, int):
    privateKey = int(privKeyHex, 16)
    return bitcoin.fast_multiply(bitcoin.G, privateKey)

def pubkey_to_address(pubKey: str, magic_byte = 0) -> str:
    pubKeyBytes = binascii.unhexlify(pubKey)
    sha256val = hashlib.sha256(pubKeyBytes).digest()
    ripemd160val = hashlib.new('ripemd160', sha256val).digest()
    return bitcoin.bin_to_b58check(ripemd160val, magic_byte)

# Replace '' as private key
private_key_wif = ''
private_key_hex = base58.b58decode_check(private_key_wif).hex()[2:]  # Decode WIF and remove '80' prefix
print("Private key (hex):", private_key_hex)

public_key = private_key_to_public_key(private_key_hex)
print("Public key (x,y) coordinates:", public_key)

compressed_public_key = bitcoin.compress(public_key)
print("Public key (hex compressed):", compressed_public_key)

address = pubkey_to_address(compressed_public_key)
print("Compressed Bitcoin address (base58check):", address)