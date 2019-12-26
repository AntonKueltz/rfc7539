from rfc7539 import _chacha20


def encrypt(key: bytes, nonce: bytes, data: bytes, counter: int = 0):
    return _chacha20.cipher(bytearray(key), bytearray(nonce), bytearray(data), len(data), counter)
