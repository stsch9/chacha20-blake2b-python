from pysodium import randombytes, crypto_stream_chacha20_ietf_xor,\
    crypto_stream_chacha20_ietf_KEYBYTES, crypto_stream_chacha20_ietf_NONCEBYTES
from blake3 import blake3
from typing import Optional
from hmac import compare_digest


class ChaCha20Blake3(object):
    KEY_SIZE = crypto_stream_chacha20_ietf_KEYBYTES
    NONCE_SIZE = crypto_stream_chacha20_ietf_NONCEBYTES
    ENCRYPTION_CONTEXT = b"ChaCha20.Encrypt()"
    MAC_CONTEXT = b"BLAKE3-256.KeyedHash()"

    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("AEAD must be created from 32 bytes")

        if len(key) != self.KEY_SIZE:
            raise ValueError(
                "The key must be exactly %s bytes long" % self.KEY_SIZE,
            )

        self._key = key

    def __bytes__(self) -> bytes:
        return self._key

    def encrypt(
            self,
            plaintext: bytes,
            aad: bytes = b"",
            nonce: Optional[bytes] = None
    ) -> [bytes, bytes, bytes]:

        if nonce is None:
            nonce = randombytes(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        encryption_key = blake3(self.ENCRYPTION_CONTEXT, key=self._key).digest()
        mac_key = blake3(self.MAC_CONTEXT + nonce, key=self._key).digest()

        ciphertext = crypto_stream_chacha20_ietf_xor(
            plaintext, nonce, encryption_key
        )

        tag = blake3(aad + ciphertext + len(aad).to_bytes(8, 'little')
                     + len(ciphertext).to_bytes(8, 'little'), key=mac_key).digest()

        del encryption_key
        del mac_key
        return nonce, ciphertext, tag

    def decrypt(
            self,
            nonce: bytes,
            ciphertext: bytes,
            tag: bytes,
            aad: bytes = b"",
    ) -> bytes:

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        encryption_key = blake3(self.ENCRYPTION_CONTEXT, key=self._key).digest()
        mac_key = blake3(self.MAC_CONTEXT + nonce, key=self._key).digest()

        computed_tag = blake3(aad + ciphertext + len(aad).to_bytes(8, 'little')
                              + len(ciphertext).to_bytes(8, 'little'), key=mac_key).digest()
        del mac_key

        if not compare_digest(computed_tag, tag):
            del encryption_key
            raise Exception("Authentication failed")
        else:
            plaintext = crypto_stream_chacha20_ietf_xor(
                ciphertext, nonce, encryption_key
            )
            del encryption_key
            return plaintext
