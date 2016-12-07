from chacha20poly1305 import _poly1305


def tag(key, msg):
    return _poly1305.tag(bytearray(key), bytearray(msg), len(msg))
