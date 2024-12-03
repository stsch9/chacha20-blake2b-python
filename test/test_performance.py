from src.chacha20_blake2b import ChaCha20Blake2b
from src.chacha20_blake3 import ChaCha20Blake3
from pysodium import crypto_aead_chacha20poly1305_ietf_encrypt
from typing import Optional
from blake3 import blake3
import time

nonce = bytes.fromhex('000000000000000000000000')
key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
aad = bytes.fromhex('76312e302e30')
plaintext = bytes(100000000)


start = time.time()
cb3 = ChaCha20Blake3(key)
cb3.encrypt(plaintext, aad, nonce)
end = time.time()
print("chacha20_blake3: %f " % (end - start))

start = time.time()
cb2 = ChaCha20Blake2b(key)
cb2.encrypt(plaintext, aad, nonce)
end = time.time()
print("chacha20_blake2b: %f " % (end - start))

start = time.time()
crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
end = time.time()
print("chacha20poly1305_ietf: %f" % (end - start))