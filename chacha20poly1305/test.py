from binascii import hexlify, unhexlify
import unittest

from chacha20poly1305 import mac


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
