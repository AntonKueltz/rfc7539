from hmac import compare_digest  # constant time comparison

from cipher import encrypt, decrypt
from mac import tag


def len_bytes(n):
    # truncate to 64 bits
    n &= 0xffffffffffffffff
    slen = ''

    while n:
        slen = slen + chr(n & 0xff)
        n >>= 8

    if len(slen) != 8:
        slen = slen + (8 - len(slen)) * chr(0x00)

    return slen


def encrypt_and_tag(key, nonce, data, adata):
    tag_key = encrypt(key, nonce, chr(0x00) * 64)
    tag_key = tag_key[:32]
    ciphertext = encrypt(key, nonce, data, counter=1)
    tag_input = len_bytes(len(adata)) + adata + len_bytes(len(ciphertext)) + ciphertext
    ciphertext_tag = tag(tag_key, tag_input)
    return ciphertext + ciphertext_tag


def verify_and_decrypt(key, nonce, data, adata):
    ciphertext, ciphertext_tag = data[:-16], data[-16:]
    tag_key = encrypt(key, nonce, chr(0x00) * 64)
    tag_key = tag_key[:32]
    tag_input = len_bytes(len(adata)) + adata + len_bytes(len(ciphertext)) + ciphertext

    if not compare_digest(tag(tag_key, tag_input), ciphertext_tag):
        print 'Got a bad tag, aborting decryption process'
        return None

    return encrypt(key, nonce, ciphertext, counter=1)
