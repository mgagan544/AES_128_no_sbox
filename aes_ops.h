// =============================================================================
// FILE        : aes_ops.h
// DESCRIPTION : AES-128 Round Operations (SubBytes, ShiftRows, MixColumns,
//               AddRoundKey, KeyExpansion) — No Lookup Tables Anywhere
// =============================================================================

#ifndef AES_OPS_H
#define AES_OPS_H

#include <stdint.h>
#include "aes_gf.h"

// AES state: 4 rows x 4 columns of bytes
// Byte ordering: state[row][col], input loaded column-major (FIPS-197 Fig.3)
typedef uint8_t AES_State[4][4];

// ---------------------------------------------------------------------------
// Key Schedule — 10 round keys derived from 128-bit key
// Round constants (RCON): powers of x in GF(2^8)
// ---------------------------------------------------------------------------
static const uint32_t RCON[11] = {
    0x00000000,  // unused (index 0)
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

// SubWord: apply sub_byte to each byte of a 32-bit word
inline uint32_t sub_word(uint32_t w) {
    return ((uint32_t)sub_byte( w >> 24         ) << 24)
         | ((uint32_t)sub_byte((w >> 16) & 0xFF ) << 16)
         | ((uint32_t)sub_byte((w >>  8) & 0xFF ) <<  8)
         | ((uint32_t)sub_byte( w        & 0xFF ));
}

// RotWord: cyclic left-shift of bytes in word [a0,a1,a2,a3] -> [a1,a2,a3,a0]
inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

// key_expansion: generate 44 round-key words (11 round keys of 128 bits each)
inline void key_expansion(const uint8_t key[16], uint32_t w[44]) {
    // First 4 words directly from key
    for (int i = 0; i < 4; i++) {
        w[i] = ((uint32_t)key[4*i  ] << 24)
             | ((uint32_t)key[4*i+1] << 16)
             | ((uint32_t)key[4*i+2] <<  8)
             | ((uint32_t)key[4*i+3]);
    }
    // Words 4..43: Rijndael key schedule
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i-1];
        if (i % 4 == 0)
            temp = sub_word(rot_word(temp)) ^ RCON[i/4];
        w[i] = w[i-4] ^ temp;
    }
}

// ---------------------------------------------------------------------------
// Byte/State conversion (FIPS-197 §3.4)
//   Column-major: in[0]=state[0][0], in[1]=state[1][0], ..., in[4]=state[0][1]
// ---------------------------------------------------------------------------
inline void bytes_to_state(const uint8_t in[16], AES_State s) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = in[r + 4*c];
}

inline void state_to_bytes(const AES_State s, uint8_t out[16]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[r + 4*c] = s[r][c];
}

// ---------------------------------------------------------------------------
// SubBytes / InvSubBytes
//   Apply sub_byte (algebraic, no LUT) to every byte of the state
// ---------------------------------------------------------------------------
inline void sub_bytes(AES_State s) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = sub_byte(s[r][c]);
}

inline void inv_sub_bytes(AES_State s) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = inv_sub_byte(s[r][c]);
}

// ---------------------------------------------------------------------------
// ShiftRows: cyclic left-shift of row r by r positions
//   Row 0: no shift
//   Row 1: shift left 1
//   Row 2: shift left 2
//   Row 3: shift left 3
// ---------------------------------------------------------------------------
inline void shift_rows(AES_State s) {
    uint8_t tmp;
    // Row 1 — shift left 1
    tmp=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=tmp;
    // Row 2 — shift left 2 (swap pairs)
    tmp=s[2][0]; s[2][0]=s[2][2]; s[2][2]=tmp;
    tmp=s[2][1]; s[2][1]=s[2][3]; s[2][3]=tmp;
    // Row 3 — shift left 3 = shift right 1
    tmp=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=tmp;
}

inline void inv_shift_rows(AES_State s) {
    uint8_t tmp;
    // Row 1 — shift right 1
    tmp=s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=tmp;
    // Row 2 — shift right 2
    tmp=s[2][0]; s[2][0]=s[2][2]; s[2][2]=tmp;
    tmp=s[2][1]; s[2][1]=s[2][3]; s[2][3]=tmp;
    // Row 3 — shift right 3 = shift left 1
    tmp=s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=tmp;
}

// ---------------------------------------------------------------------------
// MixColumns: multiply each column by the MDS matrix over GF(2^8)
//
//  [2 3 1 1]   [s0]
//  [1 2 3 1] * [s1]   (matrix multiply over GF(2^8))
//  [1 1 2 3]   [s2]
//  [3 1 1 2]   [s3]
//
//  Ensures full diffusion — each output byte depends on all 4 input bytes
// ---------------------------------------------------------------------------
inline void mix_columns(AES_State s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0=s[0][c], a1=s[1][c], a2=s[2][c], a3=s[3][c];
        s[0][c] = gf_mul(0x02,a0) ^ gf_mul(0x03,a1) ^ a2              ^ a3;
        s[1][c] = a0              ^ gf_mul(0x02,a1) ^ gf_mul(0x03,a2) ^ a3;
        s[2][c] = a0              ^ a1              ^ gf_mul(0x02,a2) ^ gf_mul(0x03,a3);
        s[3][c] = gf_mul(0x03,a0) ^ a1              ^ a2              ^ gf_mul(0x02,a3);
    }
}

// InvMixColumns: multiply by inverse MDS matrix
//  [14 11 13  9]
//  [ 9 14 11 13]
//  [13  9 14 11]
//  [11 13  9 14]
inline void inv_mix_columns(AES_State s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0=s[0][c], a1=s[1][c], a2=s[2][c], a3=s[3][c];
        s[0][c] = gf_mul(0x0E,a0)^gf_mul(0x0B,a1)^gf_mul(0x0D,a2)^gf_mul(0x09,a3);
        s[1][c] = gf_mul(0x09,a0)^gf_mul(0x0E,a1)^gf_mul(0x0B,a2)^gf_mul(0x0D,a3);
        s[2][c] = gf_mul(0x0D,a0)^gf_mul(0x09,a1)^gf_mul(0x0E,a2)^gf_mul(0x0B,a3);
        s[3][c] = gf_mul(0x0B,a0)^gf_mul(0x0D,a1)^gf_mul(0x09,a2)^gf_mul(0x0E,a3);
    }
}

// ---------------------------------------------------------------------------
// AddRoundKey: XOR state with one round key (128 bits = 4 words)
// ---------------------------------------------------------------------------
inline void add_round_key(AES_State s, const uint32_t* rk) {
    for (int c = 0; c < 4; c++) {
        s[0][c] ^= (rk[c] >> 24) & 0xFF;
        s[1][c] ^= (rk[c] >> 16) & 0xFF;
        s[2][c] ^= (rk[c] >>  8) & 0xFF;
        s[3][c] ^=  rk[c]        & 0xFF;
    }
}

// ---------------------------------------------------------------------------
// AES-128 Encrypt / Decrypt (10 rounds)
//   Encrypt: SubBytes → ShiftRows → MixColumns → AddRoundKey  (x9)
//            SubBytes → ShiftRows → AddRoundKey                (final round)
//   Decrypt: inverse operations in reverse order
// ---------------------------------------------------------------------------
inline void aes128_encrypt(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    uint32_t w[44];
    key_expansion(key, w);

    AES_State s;
    bytes_to_state(in, s);
    add_round_key(s, w);                         // Initial round key

    for (int round = 1; round <= 9; round++) {   // Rounds 1-9
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, w + 4*round);
    }
    sub_bytes(s);                                // Round 10 (no MixColumns)
    shift_rows(s);
    add_round_key(s, w + 40);

    state_to_bytes(s, out);
}

inline void aes128_decrypt(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    uint32_t w[44];
    key_expansion(key, w);

    AES_State s;
    bytes_to_state(in, s);
    add_round_key(s, w + 40);

    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, w + 4*round);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, w);

    state_to_bytes(s, out);
}

#endif // AES_OPS_H
