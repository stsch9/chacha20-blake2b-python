import unittest
from src.chacha20_blake3 import ChaCha20Blake3

T_LEN = 32


class TestChacha20Blake3(unittest.TestCase):
    def test_encryption_1(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        caead = ChaCha20Blake3(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=b'', nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('df98b1d206fcfcd535f0c228dd08197eddf9494db010abd195c9fb5ded31a0e993667b3c4a952511cdba5f2906ff869545519dd3311bdd331c4e2e0e025871b5f018da90b57427631896a2f1700ae6a0910eb67b140b1ded9825d407ab2444696c173737fa570978'))

    def test_encryption_2(self):
        plaintext = b''
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake3(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('a9289a0b71304e937b10adb036f71ed0236dc283d4ad85f73236307f2e9da3cb'))

    def test_encryption_3(self):
        plaintext = b''
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = bytes.fromhex('76312e302e30')
        caead = ChaCha20Blake3(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('28c34d7d51e39182dc869e016c4200fbcc80e55d307194e141b9a96f674ac7a6'))

    def test_encryption_4(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('010000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake3(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('7c99b91a7c586e612eb7a292fa10a136d88c3a60c1394406a83c29fa742aca746d3d88927fb347946e339543652a0a7108623f4aac97878a988de603e04100b3a051cfa0055bcc8c532f31f4d4109afb5089dc4600648987b6b5a31d95f8d5a4a2aa2e6d90f42546'))

    def test_encryption_5(self):
        plaintext = bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e')
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
        aad = b''
        caead = ChaCha20Blake3(key)
        nonce, ciphertext, tag = caead.encrypt(plaintext=plaintext, aad=aad, nonce=nonce)
        self.assertEqual(ciphertext + tag, bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a'))

    def test_decryption_1(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('df98b1d206fcfcd535f0c228dd08197eddf9494db010abd195c9fb5ded31a0e993667b3c4a952511cdba5f2906ff869545519dd3311bdd331c4e2e0e025871b5f018da90b57427631896a2f1700ae6a0910eb67b140b1ded9825d407ab2444696c173737fa570978')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake3(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_2(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('a9289a0b71304e937b10adb036f71ed0236dc283d4ad85f73236307f2e9da3cb')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake3(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, b'')

    def test_decryption_3(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('28c34d7d51e39182dc869e016c4200fbcc80e55d307194e141b9a96f674ac7a6')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        aad = bytes.fromhex('76312e302e30')
        caead = ChaCha20Blake3(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag, aad)
        self.assertEqual(plaintext, b'')

    def test_decryption_4(self):
        nonce = bytes.fromhex('010000000000000000000000')
        key = bytes.fromhex('1001000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('7c99b91a7c586e612eb7a292fa10a136d88c3a60c1394406a83c29fa742aca746d3d88927fb347946e339543652a0a7108623f4aac97878a988de603e04100b3a051cfa0055bcc8c532f31f4d4109afb5089dc4600648987b6b5a31d95f8d5a4a2aa2e6d90f42546')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake3(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_5(self):
        nonce = bytes.fromhex('000000000000000000000000')
        key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
        ciphertext_tag = bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a')
        ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
        tag = ciphertext_tag[-T_LEN:]
        caead = ChaCha20Blake3(key)
        plaintext = caead.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, bytes.fromhex('5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e'))

    def test_decryption_6(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('6018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake3(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_7(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60b')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake3(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_8(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000001')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake3(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_9(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1003000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake3(key)
            plaintext = caead.decrypt(nonce, ciphertext, tag)

    def test_decryption_10(self):
        with self.assertRaises(Exception):
            nonce = bytes.fromhex('000000000000000000000000')
            key = bytes.fromhex('1002000000000000000000000000000000000000000000000000000000000000')
            ciphertext_tag = bytes.fromhex('7018ad4acfa162d65c686170808bb0ac24d7dac5011b4c3c4211a7c41460ae55cf8c4186ecb704834ce50cb6c3f55bbee0813917b0c70c6a248bd0bbec44d0ac4a2da6b7ab61e0f3c099a212fb027b3be685962666dff2c7b484b9d8a473f8d64fb5ffcfb50fb60a')
            ciphertext = ciphertext_tag[:len(ciphertext_tag) - T_LEN]
            tag = ciphertext_tag[-T_LEN:]
            caead = ChaCha20Blake3(key)
            aad = bytes.fromhex('76312e302e30')
            plaintext = caead.decrypt(nonce, ciphertext, tag, aad)


if __name__ == '__main__':
    unittest.main()