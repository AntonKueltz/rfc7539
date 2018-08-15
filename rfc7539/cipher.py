from .util import force_bytes
from rfc7539 import _chacha20


def encrypt(key, nonce, data, counter=0):
    return _chacha20.cipher(force_bytes(key), force_bytes(nonce), force_bytes(data), len(data), counter)
