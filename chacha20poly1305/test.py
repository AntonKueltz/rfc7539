from binascii import hexlify, unhexlify
import unittest

from chacha20poly1305 import cipher, mac


class TestChaCha20(unittest.TestCase):
    # test from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00
    def test_chacha20_keystream1(self):
        key = chr(0x00) * 32
        nonce = chr(0x00) * 8
        data = chr(0x00) * 64
        expected = unhexlify(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc'
            '8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c'
            'c387b669b2ee6586'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertTrue(keystream == expected)

    def test_chacha20_keystream2(self):
        key = chr(0x00) * 31 + chr(0x01)
        nonce = chr(0x00) * 8
        data = chr(0x00) * 64
        expected = unhexlify(
            '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952'
            'ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81'
            '7e9ad275ae546963'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertTrue(keystream == expected)

    def test_chacha20_keystream3(self):
        key = chr(0x00) * 32
        nonce = chr(0x00) * 7 + chr(0x01)
        data = chr(0x00) * 60
        expected = unhexlify(
            'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1'
            '37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e'
            '445f41e3'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertTrue(keystream == expected)

    def test_chacha20_keystream4(self):
        key = chr(0x00) * 32
        nonce = chr(0x01) + chr(0x00) * 7
        data = chr(0x00) * 64
        expected = unhexlify(
            'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1'
            '38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d'
            '6bbdb0041b2f586b'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertTrue(keystream == expected)

    def test_chacha20_keystream5(self):
        key = unhexlify('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        nonce = unhexlify('0001020304050607')
        data = chr(0x00) * 256
        expected = unhexlify(
            'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56'
            'f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1'
            '5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526'
            '4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e'
            '09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750'
            '32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5'
            '07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7'
            '6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2'
            'ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab7'
            '8fab78c9'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertTrue(keystream == expected)


class TestPoly1305(unittest.TestCase):
    # test from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00
    def test_poly1305_tag1(self):
        inp = unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        key = unhexlify('746869732069732033322d62797465206b657920666f7220506f6c7931333035')
        expected = unhexlify('49ec78090e481ec6c26b33b91ccc0307')

        tag = mac.tag(key, inp)
        self.assertTrue(tag == expected)

    def test_poly1305_tag2(self):
        inp = unhexlify('48656c6c6f20776f726c6421')
        key = unhexlify('746869732069732033322d62797465206b657920666f7220506f6c7931333035')
        expected = unhexlify('a6f745008f81c916a20dcc74eef2b2f0')

        tag = mac.tag(key, inp)
        self.assertTrue(tag == expected)

if __name__ == '__main__':
    unittest.main()
