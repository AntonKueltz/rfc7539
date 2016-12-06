#include <stdlib.h>

#define byte unsigned char
#define STATE_WORDS 16

void chacha20Cipher(byte * key, byte * nonce, byte * data, size_t len);
