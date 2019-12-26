from rfc7539 import _poly1305


def tag(key: bytes, msg: bytes) -> bytes:
    return _poly1305.tag(bytearray(key), bytearray(msg), len(msg))
