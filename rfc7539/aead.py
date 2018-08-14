from hmac import compare_digest  # constant time comparison

from cipher import encrypt
from mac import tag


def _len_bytes(n):
    # truncate to 32 bits
    n &= 0xffffffff
    slen = ''

    while n:
        slen = slen + chr(n & 0xff)
        n >>= 8

    if len(slen) != 8:
        slen = slen + (8 - len(slen)) * chr(0x00)

    return slen


def _tag_data(aad, ciphertext):
    tag_data = aad + chr(0x00) * (16 - (len(aad) % 16))
    tag_data += ciphertext + chr(0x00) * (16 - (len(ciphertext) % 16))
    tag_data += _len_bytes(len(aad))
    tag_data += _len_bytes(len(ciphertext))
    return tag_data


def encrypt_and_tag(key, nonce, plaintext, aad):
    tag_key = encrypt(key, nonce, chr(0x00) * 64)
    tag_key = tag_key[:32]
    ciphertext = encrypt(key, nonce, plaintext, counter=1)
    tag_input = _tag_data(aad, ciphertext)
    mac = tag(tag_key, tag_input)
    return (ciphertext, mac)


def verify_and_decrypt(key, nonce, ciphertext, mac, aad):
    tag_key = encrypt(key, nonce, chr(0x00) * 64)
    tag_key = tag_key[:32]
    tag_input = _tag_data(aad, ciphertext)

    if not compare_digest(tag(tag_key, tag_input), mac):
        print('Got a bad tag, aborting decryption process')
        return None

    return encrypt(key, nonce, ciphertext, counter=1)
