import unittest
from src.chacha20_blake2b import ChaCha20Blake2b

T_LEN = 32


class TestChacha20Blake2b(unittest.TestCase):
    def test_encryption_1(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=b'', nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7bdb04001a8feeab7de48946f08df1cfd0ce03a719232ea7106efb8706e40d7cb6'))

    def test_encryption_2(self):
        plaintext = b''
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('a1ad6c7c4a9bb8201cf72904ebea1fed709c75ded85adaea7034bdbba1b5ec4f'))

    def test_encryption_3(self):
        plaintext = b''
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = bytes.fromhex('76312e302e30')
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('c0deb4501fe4cc651687cff8c9f5377072d4788cfe2d0f51dd97fab7b16fab84'))

    def test_encryption_4(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('010000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('db685e0ff12fafd611a832c90e6c7905598ed65babdf6d8cf7057d07b5168673727dda3ef3d6ed2520332c8036e2ce0f72c413290bc4ae41d2d398e4cb2d1f6e906e232ae471ca0ea4ade513d685a4fab9a886fa885b6f6b54ff04d66612cfdde669bd0dbda23f54'))

    def test_encryption_5(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake2b(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3'))

    def test_decryption_1(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7bdb04001a8feeab7de48946f08df1cfd0ce03a719232ea7106efb8706e40d7cb6')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_2(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('a1ad6c7c4a9bb8201cf72904ebea1fed709c75ded85adaea7034bdbba1b5ec4f')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, b'')

    def test_decryption_3(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('c0deb4501fe4cc651687cff8c9f5377072d4788cfe2d0f51dd97fab7b16fab84')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        aad = bytes.fromhex('76312e302e30')
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag, aad)
        self.assertEqual(plaintext, b'')

    def test_decryption_4(self):
        nonce = bytes.fromhex('010000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('db685e0ff12fafd611a832c90e6c7905598ed65babdf6d8cf7057d07b5168673727dda3ef3d6ed2520332c8036e2ce0f72c413290bc4ae41d2d398e4cb2d1f6e906e232ae471ca0ea4ade513d685a4fab9a886fa885b6f6b54ff04d66612cfdde669bd0dbda23f54')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_5(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake2b(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_6(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('408319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake2b(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_7(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b4')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake2b(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_8(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000001')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake2b(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_9(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1003000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake2b(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_10(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake2b(key)
            aad = bytes.fromhex('76312e302e30')
            plaintext = caead.decrypt(nonce, ciphertext, tag, aad)


if __name__ == '__main__':
    unittest.main()