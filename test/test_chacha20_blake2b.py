import unittest
from src.chacha20_blake2b import ChaCha20Blake2b

T_LEN = 32

class TestChacha20Blake2b(unittest.TestCase):
    def test_encryption(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=b'', nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7bdb04001a8feeab7de48946f08df1cfd0ce03a719232ea7106efb8706e40d7cb6'))

    def test_decryption(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('a1ad6c7c4a9bb8201cf72904ebea1fed709c75ded85adaea7034bdbba1b5ec4f')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, b'')


if __name__ == '__main__':
    unittest.main()