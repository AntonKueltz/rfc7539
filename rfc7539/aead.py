from hmac import compare_digest  # constant time comparison
from logging import getLogger
from struct import pack

from .cipher import encrypt
from .mac import tag
from .util import force_bytes


class BadTagException(Exception):
    def __init__(self, message):
        super(BadTagException, self).__init__(message)


def _len_bytes(n):
    # truncate to 32 bits
    n &= 0xffffffff
    slen = b''

    while n:
        slen = slen + pack('B', n & 0xff)
        n >>= 8

    if len(slen) != 8:
        slen = slen + (8 - len(slen)) * b'\x00'

    return slen


def _pad16(x):
    if len(x) % 16 == 0:
        return b''
    else:
        return b'\x00' * (16 - (len(x) % 16))


def _tag_data(aad, ciphertext):
    tag_data = aad + _pad16(aad)
    tag_data += ciphertext + _pad16(ciphertext)
    tag_data += _len_bytes(len(aad))
    tag_data += _len_bytes(len(ciphertext))
    return tag_data


def encrypt_and_tag(key, nonce, plaintext, aad):
    aad = force_bytes(aad)
    tag_key = encrypt(key, nonce, b'\x00' * 64)
    tag_key = tag_key[:32]
    ciphertext = encrypt(key, nonce, plaintext, counter=1)
    tag_input = _tag_data(aad, ciphertext)
    mac = tag(tag_key, tag_input)
    return (ciphertext, mac)


def verify_and_decrypt(key, nonce, ciphertext, mac, aad):
    aad = force_bytes(aad)
    tag_key = encrypt(key, nonce, b'\x00' * 64)
    tag_key = tag_key[:32]
    tag_input = _tag_data(aad, ciphertext)

    if not compare_digest(tag(tag_key, tag_input), mac):
        raise BadTagException('Got a bad tag, aborting decryption process')

    return encrypt(key, nonce, ciphertext, counter=1)
