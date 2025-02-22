// blake2b.c
#include "../../include/blake2b.h"
#include <string.h>

// BLAKE2b 초기화 벡터
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

// 시그마 테이블
static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static void store64(uint8_t *dst, uint64_t w) {
    dst[0] = (uint8_t)w; w >>= 8;
    dst[1] = (uint8_t)w; w >>= 8;
    dst[2] = (uint8_t)w; w >>= 8;
    dst[3] = (uint8_t)w; w >>= 8;
    dst[4] = (uint8_t)w; w >>= 8;
    dst[5] = (uint8_t)w; w >>= 8;
    dst[6] = (uint8_t)w; w >>= 8;
    dst[7] = (uint8_t)w;
}

static uint64_t rotr64(uint64_t w, unsigned c) {
    return (w >> c) | (w << (64 - c));
}

#define G(r,i,a,b,c,d)                      \
    do {                                    \
        a = a + b + m[blake2b_sigma[r][2*i+0]]; \
        d = rotr64(d ^ a, 32);             \
        c = c + d;                         \
        b = rotr64(b ^ c, 24);             \
        a = a + b + m[blake2b_sigma[r][2*i+1]]; \
        d = rotr64(d ^ a, 16);             \
        c = c + d;                         \
        b = rotr64(b ^ c, 63);             \
    } while(0)

static void blake2b_compress(blake2b_state *S, const uint8_t block[128]) {
    uint64_t m[16];
    uint64_t v[16];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint64_t) block[8 * i + 0]) |
               ((uint64_t) block[8 * i + 1] <<  8) |
               ((uint64_t) block[8 * i + 2] << 16) |
               ((uint64_t) block[8 * i + 3] << 24) |
               ((uint64_t) block[8 * i + 4] << 32) |
               ((uint64_t) block[8 * i + 5] << 40) |
               ((uint64_t) block[8 * i + 6] << 48) |
               ((uint64_t) block[8 * i + 7] << 56);
    }

    for (i = 0; i < 8; ++i) {
        v[i] = S->h[i];
    }

    v[8]  = blake2b_IV[0];
    v[9]  = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    for (i = 0; i < 12; ++i) {
        G(i, 0, v[0], v[4], v[8],  v[12]);
        G(i, 1, v[1], v[5], v[9],  v[13]);
        G(i, 2, v[2], v[6], v[10], v[14]);
        G(i, 3, v[3], v[7], v[11], v[15]);
        G(i, 4, v[0], v[5], v[10], v[15]);
        G(i, 5, v[1], v[6], v[11], v[12]);
        G(i, 6, v[2], v[7], v[8],  v[13]);
        G(i, 7, v[3], v[4], v[9],  v[14]);
    }

    for (i = 0; i < 8; ++i) {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }
}

int blake2b_init(blake2b_state *S, size_t outlen) {
    if ((!outlen) || (outlen > 64)) return -1;

    memset(S, 0, sizeof(blake2b_state));
    for (size_t i = 0; i < 8; i++)
        S->h[i] = blake2b_IV[i];

    S->outlen = outlen;
    return 0;
}

int blake2b_update(blake2b_state *S, const void *in, size_t inlen) {
    const uint8_t *input = (const uint8_t *)in;

    if (S->buflen + inlen > 128) {
        size_t fill = 128 - S->buflen;
        memcpy(S->buf + S->buflen, input, fill);
        S->t[0] += 128;
        if (S->t[0] < 128)
            S->t[1]++;
        blake2b_compress(S, S->buf);
        input += fill;
        inlen -= fill;
        S->buflen = 0;

        while (inlen > 128) {
            S->t[0] += 128;
            if (S->t[0] < 128)
                S->t[1]++;
            blake2b_compress(S, input);
            input += 128;
            inlen -= 128;
        }
    }

    if (inlen > 0) {
        memcpy(S->buf + S->buflen, input, inlen);
        S->buflen += inlen;
    }

    return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[64];

    if (S->outlen != outlen) return -1;

    if (S->buflen > 0) {
        size_t i;
        if (S->buflen < 128) {
            for (i = S->buflen; i < 128; i++)
                S->buf[i] = 0;
        }
        S->t[0] += S->buflen;
        if (S->t[0] < S->buflen)
            S->t[1]++;
        S->f[0] = (uint64_t)-1;
        blake2b_compress(S, S->buf);
    }

    for (size_t i = 0; i < 8; i++) {
        store64(buffer + sizeof(uint64_t) * i, S->h[i]);
    }

    memcpy(out, buffer, S->outlen);
    return 0;
}