from .util import force_bytes
from rfc7539 import _poly1305


def tag(key, msg):
    return _poly1305.tag(force_bytes(key), force_bytes(msg), len(msg))
