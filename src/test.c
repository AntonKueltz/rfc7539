#include <stdio.h>

#include "_chacha20.h"
#include "_poly1305.h"

int main(int argc, char * argv[]) {
    // https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00
    unsigned char key1[32] = {0x00};
    unsigned char nonce[8] = {0x00};
    unsigned char in[64] = {0x00};
    unsigned char out[64];
    unsigned int inLen = 64;
    uint64_t counter = 0;

    ChaCha20XOR(out, in, inLen, key1, nonce, counter);

    printf("ChaCha20 Keystream:\n");
    for(unsigned int i = 0; i < inLen; i++) { printf("%02x", out[i]); }
    printf("\n\n");

    poly1305_state state;
    unsigned char key2[32] = {
        0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20,
        0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x50, 0x6f, 0x6c, 0x79, 0x31, 0x33, 0x30, 0x35
    };
    unsigned char input[32] = { 0x00 };
    unsigned char mac[16];

    Poly1305Init(&state, key2);
    Poly1305Update(&state, input, 32);
    Poly1305Finish(&state, mac);

    printf("Poly1305 MAC:\n");
    for(unsigned i = 0; i < 16; i++) { printf("%02x", mac[i]); }
    printf("\n");
}
