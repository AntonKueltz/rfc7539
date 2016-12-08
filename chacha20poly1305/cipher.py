from chacha20poly1305 import _chacha20


def encrypt(key, nonce, data, counter=0):
    return _chacha20.cipher(bytearray(key), bytearray(nonce), bytearray(data), len(data), counter)
