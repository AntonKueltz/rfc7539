from binascii import hexlify, unhexlify
import unittest

from rfc7539 import aead, cipher, mac


class TestChaCha20Keystream(unittest.TestCase):
    # test from https://tools.ietf.org/html/rfc7539#appendix-A.1
    def test_chacha20_keystream1(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        data = b'\x00' * 64
        expected = unhexlify(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc'
            '8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c'
            'c387b669b2ee6586'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertEqual(keystream, expected)

    def test_chacha20_keystream2(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        data = b'\x00' * 64
        expected = unhexlify(
            '9f07e7be5551387a98ba977c732d080d'
            'cb0f29a048e3656912c6533e32ee7aed'
            '29b721769ce64e43d57133b074d839d5'
            '31ed1f28510afb45ace10a1f4b794d6f'
        )

        keystream = cipher.encrypt(key, nonce, data, counter=1)
        self.assertEqual(keystream, expected)

    def test_chacha20_keystream3(self):
        key = b'\x00' * 31 + b'\x01'
        nonce = b'\x00' * 12
        data = b'\x00' * 64
        expected = unhexlify(
            '3aeb5224ecf849929b9d828db1ced4dd'
            '832025e8018b8160b82284f3c949aa5a'
            '8eca00bbb4a73bdad192b5c42f73f2fd'
            '4e273644c8b36125a64addeb006c13a0'
        )

        keystream = cipher.encrypt(key, nonce, data, counter=1)
        self.assertEqual(keystream, expected)

    def test_chacha20_keystream4(self):
        key = b'\x00' + b'\xff' + b'\x00' * 30
        nonce = b'\x00' * 12
        data = b'\x00' * 64
        expected = unhexlify(
            '72d54dfbf12ec44b362692df94137f32'
            '8fea8da73990265ec1bbbea1ae9af0ca'
            '13b25aa26cb4a648cb9b9d1be65b2c09'
            '24a66c54d545ec1b7374f4872e99f096'
        )

        keystream = cipher.encrypt(key, nonce, data, counter=2)
        self.assertEqual(keystream, expected)

    def test_chacha20_keystream5(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 11 + b'\x02'
        data = b'\x00' * 64
        expected = unhexlify(
            'c2c64d378cd536374ae204b9ef933fcd'
            '1a8b2288b3dfa49672ab765b54ee27c7'
            '8a970e0e955c14f3a88e741b97c286f7'
            '5f8fc299e8148362fa198a39531bed6d'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertEqual(keystream, expected)


class TestChaCha20Encryption(unittest.TestCase):
    # test from https://tools.ietf.org/html/rfc7539#appendix-A.2
    def test_chacha20_encryption1(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        data = b'\x00' * 64
        expected = unhexlify(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc'
            '8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c'
            'c387b669b2ee6586'
        )

        keystream = cipher.encrypt(key, nonce, data)
        self.assertEqual(keystream, expected)

    def test_chacha20_keystream2(self):
        key = b'\x00' * 31 + b'\x01'
        nonce = b'\x00' * 11 + b'\x02'
        data = 'Any submission to the IETF intended by the Contributor for publication as all ' \
               'or part of an IETF Internet-Draft or RFC and any statement made within the ' \
               'context of an IETF activity is considered an "IETF Contribution". Such ' \
               'statements include oral statements in IETF sessions, as well as written and ' \
               'electronic communications made at any time or place, which are addressed to'
        expected = unhexlify(
            'a3fbf07df3fa2fde4f376ca23e827370'
            '41605d9f4f4f57bd8cff2c1d4b7955ec'
            '2a97948bd3722915c8f3d337f7d37005'
            '0e9e96d647b7c39f56e031ca5eb6250d'
            '4042e02785ececfa4b4bb5e8ead0440e'
            '20b6e8db09d881a7c6132f420e527950'
            '42bdfa7773d8a9051447b3291ce1411c'
            '680465552aa6c405b7764d5e87bea85a'
            'd00f8449ed8f72d0d662ab052691ca66'
            '424bc86d2df80ea41f43abf937d3259d'
            'c4b2d0dfb48a6c9139ddd7f76966e928'
            'e635553ba76c5c879d7b35d49eb2e62b'
            '0871cdac638939e25e8a1e0ef9d5280f'
            'a8ca328b351c3c765989cbcf3daa8b6c'
            'cc3aaf9f3979c92b3720fc88dc95ed84'
            'a1be059c6499b9fda236e7e818b04b0b'
            'c39c1e876b193bfe5569753f88128cc0'
            '8aaa9b63d1a16f80ef2554d7189c411f'
            '5869ca52c5b83fa36ff216b9c1d30062'
            'bebcfd2dc5bce0911934fda79a86f6e6'
            '98ced759c3ff9b6477338f3da4f9cd85'
            '14ea9982ccafb341b2384dd902f3d1ab'
            '7ac61dd29c6f21ba5b862f3730e37cfd'
            'c4fd806c22f221'
        )

        keystream = cipher.encrypt(key, nonce, data, counter=1)
        self.assertEqual(keystream, expected)

    def test_chacha20_encryption3(self):
        key = unhexlify(
            '1c9240a5eb55d38af333888604f6b5f0'
            '473917c1402b80099dca5cbc207075c0'
        )
        nonce = b'\x00' * 11 + b'\x02'
        data = '\'Twas brillig, and the slithy toves\x0aDid gyre and gimble in the wabe:\x0a' \
               'All mimsy were the borogoves,\x0aAnd the mome raths outgrabe.'
        expected = unhexlify(
            '62e6347f95ed87a45ffae7426f27a1df'
            '5fb69110044c0d73118effa95b01e5cf'
            '166d3df2d721caf9b21e5fb14c616871'
            'fd84c54f9d65b283196c7fe4f60553eb'
            'f39c6402c42234e32a356b3e764312a6'
            '1a5532055716ead6962568f87d3f3f77'
            '04c6a8d1bcd1bf4d50d6154b6da731b1'
            '87b58dfd728afa36757a797ac188d1'
        )

        keystream = cipher.encrypt(key, nonce, data, counter=42)
        self.assertEqual(keystream, expected)


class TestPoly1305(unittest.TestCase):
    # https://tools.ietf.org/html/rfc7539#appendix-A.3
    def test_poly1305_tag1(self):
        inp = b'\x00' * 64
        key = b'\x00' * 32
        expected = b'\x00' * 16

        tag = mac.tag(key, inp)
        self.assertEqual(tag, expected)

    def test_poly1305_tag2(self):
        inp = 'Any submission to the IETF intended by the Contributor for publication as all ' \
              'or part of an IETF Internet-Draft or RFC and any statement made within the ' \
              'context of an IETF activity is considered an "IETF Contribution". Such ' \
              'statements include oral statements in IETF sessions, as well as written and ' \
              'electronic communications made at any time or place, which are addressed to'
        key = unhexlify(
            '00000000000000000000000000000000'
            '36e5f6b5c5e06070f0efca96227a863e'
        )
        expected = unhexlify('36e5f6b5c5e06070f0efca96227a863e')

        tag = mac.tag(key, inp)
        self.assertEqual(tag, expected)

    def test_poly1305_tag3(self):
        inp = 'Any submission to the IETF intended by the Contributor for publication as all ' \
              'or part of an IETF Internet-Draft or RFC and any statement made within the ' \
              'context of an IETF activity is considered an "IETF Contribution". Such ' \
              'statements include oral statements in IETF sessions, as well as written and ' \
              'electronic communications made at any time or place, which are addressed to'
        key = unhexlify(
            '36e5f6b5c5e06070f0efca96227a863e'
            '00000000000000000000000000000000'
        )
        expected = unhexlify('f3477e7cd95417af89a6b8794c310cf0')

        tag = mac.tag(key, inp)
        self.assertEqual(tag, expected)

    def test_poly1305_tag4(self):
        inp = '\'Twas brillig, and the slithy toves\x0aDid gyre and gimble in the wabe:\x0a' \
              'All mimsy were the borogoves,\x0aAnd the mome raths outgrabe.'
        key = unhexlify(
            '1c9240a5eb55d38af333888604f6b5f0'
            '473917c1402b80099dca5cbc207075c0'
        )
        expected = unhexlify('4541669a7eaaee61e708dc7cbcc5eb62')

        tag = mac.tag(key, inp)
        self.assertEqual(tag, expected)


class TestPoly1305Keygen(unittest.TestCase):
    # test from https://tools.ietf.org/html/rfc7539#appendix-A.4
    def test_poly1305_keygen1(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        expected = unhexlify(
            '76b8e0ada0f13d90405d6ae55386bd28'
            'bdd219b8a08ded1aa836efcc8b770dc7'
        )

        tag_key = cipher.encrypt(key, nonce, b'\x00' * 64)[:32]
        self.assertEqual(tag_key, expected)

    def test_poly1305_keygen2(self):
        key = b'\x00' * 31 + b'\x01'
        nonce = b'\x00' * 11 + b'\x02'
        expected = unhexlify(
            'ecfa254f845f647473d3cb140da9e876'
            '06cb33066c447b87bc2666dde3fbb739'
        )

        tag_key = cipher.encrypt(key, nonce, b'\x00' * 64)[:32]
        self.assertEqual(tag_key, expected)

    def test_poly1305_keygen3(self):
        key = unhexlify(
            '1c9240a5eb55d38af333888604f6b5f0'
            '473917c1402b80099dca5cbc207075c0'
        )
        nonce = b'\x00' * 11 + b'\x02'
        expected = unhexlify(
            '965e3bc6f9ec7ed9560808f4d229f94b'
            '137ff275ca9b3fcbdd59deaad23310ae'
        )

        tag_key = cipher.encrypt(key, nonce, b'\x00' * 64)[:32]
        self.assertEqual(tag_key, expected)


class TestAEAD(unittest.TestCase):
    # test from https://tools.ietf.org/html/rfc7539#appendix-A.5
    def test_aead_decryption(self):
        key = unhexlify(
            '1c9240a5eb55d38af333888604f6b5f0'
            '473917c1402b80099dca5cbc207075c0'
        )
        nonce = unhexlify('000000000102030405060708')
        aad = unhexlify('f33388860000000000004e91')
        tag = unhexlify('eead9d67890cbb22392336fea1851f38')
        ciphertext = unhexlify(
            '64a0861575861af460f062c79be643bd'
            '5e805cfd345cf389f108670ac76c8cb2'
            '4c6cfc18755d43eea09ee94e382d26b0'
            'bdb7b73c321b0100d4f03b7f355894cf'
            '332f830e710b97ce98c8a84abd0b9481'
            '14ad176e008d33bd60f982b1ff37c855'
            '9797a06ef4f0ef61c186324e2b350638'
            '3606907b6a7c02b0f9f6157b53c867e4'
            'b9166c767b804d46a59b5216cde7a4e9'
            '9040c5a40433225ee282a1b0a06c523e'
            'af4534d7f83fa1155b0047718cbc546a'
            '0d072b04b3564eea1b422273f548271a'
            '0bb2316053fa76991955ebd63159434e'
            'cebb4e466dae5a1073a6727627097a10'
            '49e617d91d361094fa68f0ff77987130'
            '305beaba2eda04df997b714d6c6f2c29'
            'a6ad5cb4022b02709b'
        )
        expected = unhexlify(
            '496e7465726e65742d44726166747320'
            '61726520647261667420646f63756d65'
            '6e74732076616c696420666f72206120'
            '6d6178696d756d206f6620736978206d'
            '6f6e74687320616e64206d6179206265'
            '20757064617465642c207265706c6163'
            '65642c206f72206f62736f6c65746564'
            '206279206f7468657220646f63756d65'
            '6e747320617420616e792074696d652e'
            '20497420697320696e617070726f7072'
            '6961746520746f2075736520496e7465'
            '726e65742d4472616674732061732072'
            '65666572656e6365206d617465726961'
            '6c206f7220746f206369746520746865'
            '6d206f74686572207468616e20617320'
            '2fe2809c776f726b20696e2070726f67'
            '726573732e2fe2809d'
        )

        plaintext = aead.verify_and_decrypt(key, nonce, ciphertext, tag, aad)
        self.assertEqual(plaintext, expected)


if __name__ == '__main__':
    unittest.main()
