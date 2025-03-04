/**
 * @brief AES-192
 *
 *        BLOCK SIZE = 16
 *        KEY SIZE = 24
 *        NUMBER OF ROUND = 12
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* benchmark code */
static inline uint64_t cycles()
{
    uint64_t cntvct;
    asm volatile("mrs %0, cntvct_el0" : "=r"(cntvct));
    return cntvct;
}

#define xtimes(state) (((state) << 1) ^ (((state) >> 7) * 0x1b))

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static void subbytes(uint8_t state[16])
{
    state[0]  = sbox[state[0]];
    state[1]  = sbox[state[1]];
    state[2]  = sbox[state[2]];
    state[3]  = sbox[state[3]];
    state[4]  = sbox[state[4]];
    state[5]  = sbox[state[5]];
    state[6]  = sbox[state[6]];
    state[7]  = sbox[state[7]];
    state[8]  = sbox[state[8]];
    state[9]  = sbox[state[9]];
    state[10] = sbox[state[10]];
    state[11] = sbox[state[11]];
    state[12] = sbox[state[12]];
    state[13] = sbox[state[13]];
    state[14] = sbox[state[14]];
    state[15] = sbox[state[15]];
}

static void shiftrows(uint8_t state[16])
{
    uint8_t temp;

    /* second row: shift 1 */
    temp      = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    /* third row: shift 2 */
    temp      = state[10];
    state[10] = state[2];
    state[2]  = temp;
    temp      = state[14];
    state[14] = state[6];
    state[6]  = temp;

    /* fourth row: shift 3 */
    temp      = state[3];
    state[3]  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = temp;
}

static void mixcolumns(uint8_t state[16])
{
    uint8_t t[16];

    memcpy(t, state, 16);

    /* first column */
    state[0] = xtimes(t[0] ^ t[1]) ^ t[1] ^ t[2] ^ t[3];
    state[1] = t[0] ^ xtimes(t[1] ^ t[2]) ^ t[2] ^ t[3];
    state[2] = t[0] ^ t[1] ^ xtimes(t[2] ^ t[3]) ^ t[3];
    state[3] = t[0] ^ t[1] ^ t[2] ^ xtimes(t[3] ^ t[0]);

    /* second column */
    state[4] = xtimes(t[4] ^ t[5]) ^ t[5] ^ t[6] ^ t[7];
    state[5] = t[4] ^ xtimes(t[5] ^ t[6]) ^ t[6] ^ t[7];
    state[6] = t[4] ^ t[5] ^ xtimes(t[6] ^ t[7]) ^ t[7];
    state[7] = t[4] ^ t[5] ^ t[6] ^ xtimes(t[7] ^ t[4]);

    /* third column */
    state[8]  = xtimes(t[8] ^ t[9]) ^ t[9] ^ t[10] ^ t[11];
    state[9]  = t[8] ^ xtimes(t[9] ^ t[10]) ^ t[10] ^ t[11];
    state[10] = t[8] ^ t[9] ^ xtimes(t[10] ^ t[11]) ^ t[11];
    state[11] = t[8] ^ t[9] ^ t[10] ^ xtimes(t[11] ^ t[8]);

    /* fourth column */
    state[12] = xtimes(t[12] ^ t[13]) ^ t[13] ^ t[14] ^ t[15];
    state[13] = t[12] ^ xtimes(t[13] ^ t[14]) ^ t[14] ^ t[15];
    state[14] = t[12] ^ t[13] ^ xtimes(t[14] ^ t[15]) ^ t[15];
    state[15] = t[12] ^ t[13] ^ t[14] ^ xtimes(t[15] ^ t[12]);
}

static void addroundkey(uint8_t state[16], const uint8_t key[16])
{
    state[0] ^= key[0];
    state[1] ^= key[1];
    state[2] ^= key[2];
    state[3] ^= key[3];
    state[4] ^= key[4];
    state[5] ^= key[5];
    state[6] ^= key[6];
    state[7] ^= key[7];
    state[8] ^= key[8];
    state[9] ^= key[9];
    state[10] ^= key[10];
    state[11] ^= key[11];
    state[12] ^= key[12];
    state[13] ^= key[13];
    state[14] ^= key[14];
    state[15] ^= key[15];
}

void keyexpansion(uint8_t rkey[13 * 16], const uint8_t mkey[16])
{
    memset(rkey, 0, 13 * 16);
    memcpy(rkey, mkey, 24);

    for (uint8_t r = 24, idx_rcon = 1; r < 13 * 16; r += 24, idx_rcon++)
    {
        rkey[r + 0] = rkey[r - 24] ^ sbox[rkey[r - 3]] ^ rcon[idx_rcon];
        rkey[r + 1] = rkey[r - 23] ^ sbox[rkey[r - 2]];
        rkey[r + 2] = rkey[r - 22] ^ sbox[rkey[r - 1]];
        rkey[r + 3] = rkey[r - 21] ^ sbox[rkey[r - 4]];

        rkey[r + 4] = rkey[r - 20] ^ rkey[r + 0];
        rkey[r + 5] = rkey[r - 19] ^ rkey[r + 1];
        rkey[r + 6] = rkey[r - 18] ^ rkey[r + 2];
        rkey[r + 7] = rkey[r - 17] ^ rkey[r + 3];

        rkey[r + 8]  = rkey[r - 16] ^ rkey[r + 4];
        rkey[r + 9]  = rkey[r - 15] ^ rkey[r + 5];
        rkey[r + 10] = rkey[r - 14] ^ rkey[r + 6];
        rkey[r + 11] = rkey[r - 13] ^ rkey[r + 7];

        rkey[r + 12] = rkey[r - 12] ^ rkey[r + 8];
        rkey[r + 13] = rkey[r - 11] ^ rkey[r + 9];
        rkey[r + 14] = rkey[r - 10] ^ rkey[r + 10];
        rkey[r + 15] = rkey[r - 9] ^ rkey[r + 11];

        rkey[r + 16] = rkey[r - 8] ^ rkey[r + 12];
        rkey[r + 17] = rkey[r - 7] ^ rkey[r + 13];
        rkey[r + 18] = rkey[r - 6] ^ rkey[r + 14];
        rkey[r + 19] = rkey[r - 5] ^ rkey[r + 15];

        rkey[r + 20] = rkey[r - 4] ^ rkey[r + 16];
        rkey[r + 21] = rkey[r - 3] ^ rkey[r + 17];
        rkey[r + 22] = rkey[r - 2] ^ rkey[r + 18];
        rkey[r + 23] = rkey[r - 1] ^ rkey[r + 19];
    }

    /* final key expansion, 192 = 8 * 24 */
    rkey[192] = rkey[168] ^ sbox[rkey[189]] ^ rcon[8];
    rkey[193] = rkey[169] ^ sbox[rkey[190]];
    rkey[194] = rkey[170] ^ sbox[rkey[191]];
    rkey[195] = rkey[171] ^ sbox[rkey[188]];
    rkey[196] = rkey[172] ^ rkey[192];
    rkey[197] = rkey[173] ^ rkey[193];
    rkey[198] = rkey[174] ^ rkey[194];
    rkey[199] = rkey[175] ^ rkey[195];
    rkey[200] = rkey[176] ^ rkey[196];
    rkey[201] = rkey[177] ^ rkey[197];
    rkey[202] = rkey[178] ^ rkey[198];
    rkey[203] = rkey[179] ^ rkey[199];
    rkey[204] = rkey[180] ^ rkey[200];
    rkey[205] = rkey[181] ^ rkey[201];
    rkey[206] = rkey[182] ^ rkey[202];
    rkey[207] = rkey[183] ^ rkey[203];
}

void cipher(uint8_t       state[16],
            const uint8_t msg[16],
            const uint8_t rkey[13 * 16])
{
    memset(state, 0, 16);
    memcpy(state, msg, 16);

    addroundkey(state, rkey);

    for (int i = 1; i < 12; i++)
    {
        subbytes(state);
        shiftrows(state);
        mixcolumns(state);
        addroundkey(state, rkey + (i * 16));
    }
    subbytes(state);
    shiftrows(state);
    addroundkey(state, rkey + (12 * 16));
}

int main()
{
    printf("========== AES-192 Benchmark (count = 100000) ==========\n");

    uint8_t msg[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    const uint8_t ct[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc};

    const uint8_t mkey[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};

    uint8_t state[16];
    uint8_t rkey[13 * 16];

    uint64_t start, end;

    start = cycles();
    for (int i = 0; i < 100000; i++)
    {
        keyexpansion(rkey, mkey);
    }
    end = cycles();
    printf("keyexpansion ......................... %llu cycles\n", end - start);

    start = cycles();
    for (int i = 0; i < 100000; i++)
    {
        cipher(state, msg, rkey);
    }
    end = cycles();
    printf("cipher ............................... %llu cycles\n", end - start);

    return 0;
}