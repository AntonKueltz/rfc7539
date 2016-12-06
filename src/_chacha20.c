#include "_chacha20.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t circularShift(uint32_t x, unsigned shiftAmount) {
    return (x << (shiftAmount)) | (x >> (8 * sizeof(uint32_t) - shiftAmount));
}

void quarterRound(uint32_t * state, unsigned i, unsigned j, unsigned k, unsigned l) {
    uint32_t a = state[i], b = state[j], c = state[k], d = state[l];
    a += b; d ^= a; d = circularShift(d, 16);
    c += d; b ^= c; b = circularShift(b, 12);
    a += b; d ^= a; d = circularShift(d, 8);
    c += d; b ^= c; b = circularShift(b, 7);
    state[i] = a; state[j] = b; state[k] = c; state[l] = d;
}

void loadWord(byte * bytes, uint32_t * state, unsigned stateIndex, unsigned byteIndex) {
    uint32_t word = bytes[byteIndex];
    word |= bytes[byteIndex+1] << 8;
    word |= bytes[byteIndex+2] << 16;
    word |= bytes[byteIndex+3] << 24;
    state[stateIndex] = word;
}

// https://tools.ietf.org/html/rfc7539
void initState(uint32_t * state, byte * key, uint32_t counter, byte * nonce) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for(unsigned char i = 4; i < 12; i++) {
        loadWord(key, state, i, (i-4) * 4);
    }

    state[12] = counter;

    for(unsigned char i = 13; i < 16; i++) {
        loadWord(nonce, state, i, (i-13) * 4);
    }
}

byte * serialize(uint32_t * state) {
    byte * stream = (byte *)malloc(4 * STATE_WORDS * sizeof(uint32_t));

    for(unsigned char i = 0; i < 4 * STATE_WORDS; i++) {
        unsigned char byteIndex = i % 4;
        uint32_t mask = 0xff << (byteIndex * 8);
        stream[i] = (mask & state[i / 4]) >> (byteIndex * 8);
    }

    return stream;
}

byte * chacha20Stream(byte * key, uint32_t counter, byte * nonce) {
    uint32_t * state = (uint32_t *)malloc(STATE_WORDS * sizeof(uint32_t));
    initState(state, key, counter, nonce);
    uint32_t * workingState = (uint32_t *)malloc(STATE_WORDS * sizeof(uint32_t));
    memcpy(workingState, state, STATE_WORDS * sizeof(uint32_t));

    for(unsigned char i = 0; i < 10; i++) {
        quarterRound(workingState, 0, 4, 8, 12);
        quarterRound(workingState, 1, 5, 9, 13);
        quarterRound(workingState, 2, 6, 10, 14);
        quarterRound(workingState, 3, 7, 11, 15);
        quarterRound(workingState, 0, 5, 10, 15);
        quarterRound(workingState, 1, 6, 11, 12);
        quarterRound(workingState, 2, 7, 8, 13);
        quarterRound(workingState, 3, 4, 9, 14);
    }

    for(unsigned char i = 0; i < STATE_WORDS; i++) {
        state[i] = (state[i] + workingState[i]) & 0xffffffff;
    }

    free(workingState);
    byte * stream = serialize(state);
    free(state);
    return stream;
}

void chacha20Cipher(byte * key, byte * nonce, byte * data, size_t len) {
    uint32_t counter = 0x00000001;

    for(uint32_t j = 0; j <= (len / 64 - 1); j++) {
        byte * keyStream = chacha20Stream(key, counter+j, nonce);

        for(uint32_t i = j*64; i <= (j * 64 + 63); i++) {
            data[i] ^= keyStream[i % 64];
        }

        free(keyStream);
    }

    if((len % 64) != 0) {
        uint32_t j = len / 64;
        byte * keyStream = chacha20Stream(key, counter+j, nonce);

        for(uint32_t i = j*64; i < len; i++) {
            data[i] ^= keyStream[i % 64];
        }
        
        free(keyStream);
    }
}



// gcc -std=c99 chacha.c
int main() {
    // tests vectors taken from rfc7539
    printf("Circular Shift:\n0x%x\n\n", circularShift(0x7998bfda, 7));

    uint32_t state[16] = {
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
    };

    quarterRound(state, 2, 7, 8, 13);
    printf("State After QUARTERROUND(2, 7, 8, 13):\n");
    printf("0x%x 0x%x 0x%x 0x%x\n", state[0], state[1], state[2], state[3]);
    printf("0x%x 0x%x 0x%x 0x%x\n", state[4], state[5], state[6], state[7]);
    printf("0x%x 0x%x 0x%x 0x%x\n", state[8], state[9], state[10], state[11]);
    printf("0x%x 0x%x 0x%x 0x%x\n\n", state[12], state[13], state[14], state[15]);

    byte key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    byte nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t counter = 0x00000001;

    initState(state, key, counter, nonce);
    printf("State After Key Setup:\n");
    printf("0x%x 0x%x 0x%x 0x%x\n", state[0], state[1], state[2], state[3]);
    printf("0x%08x 0x%08x 0x%08x 0x%08x\n", state[4], state[5], state[6], state[7]);
    printf("0x%x 0x%x 0x%x 0x%x\n", state[8], state[9], state[10], state[11]);
    printf("0x%08x 0x%08x 0x%08x 0x%08x\n\n", state[12], state[13], state[14], state[15]);

    byte * stream = chacha20Stream(key, counter, nonce);
    printf("ChaCha20 Stream:\n");
    for(unsigned char i = 0; i < 4 * STATE_WORDS; i++) printf("%x:", stream[i]);
    printf("\n\n");

    byte data[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    byte nonce2[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    chacha20Cipher(key, nonce2, data, strlen(data));
    printf("ChaCha20 Ciphertext:\n");
    for(unsigned char i = 0; i < strlen(data); i++) printf("%x:", data[i]);
    printf("\n");

    return 0;
}
