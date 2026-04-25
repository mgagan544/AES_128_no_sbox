// =============================================================================
// FILE        : aes_gf.h
// DESCRIPTION : GF(2^8) Arithmetic for AES S-Box (No Lookup Table)
//
//  The AES irreducible polynomial:  m(x) = x^8 + x^4 + x^3 + x + 1  (0x11B)
//
//  WHY GF(2^8)?
//    - Computers work in bits (base 2)  →  GF(2) maps to XOR/AND gates
//    - One byte = 8 bits = 256 values   →  GF(2^8) has exactly 256 elements
//    - Every byte maps 1-to-1 to GF(2^8), arithmetic stays within one byte
//
//  S-BOX = two steps:
//    Step 1: b = a^{-1} in GF(2^8)         [NONLINEAR — this replaces the LUT]
//    Step 2: s = affine_transform(b)        [LINEAR  — XOR of rotated bits + 0x63]
//
//  Inverse a^{-1} via Fermat's Little Theorem: a^{255} = 1  =>  a^{-1} = a^{254}
//    a^{254} = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
//    (7 squarings — each squaring is LINEAR in GF(2), 6 multiplications)
// =============================================================================

#ifndef AES_GF_H
#define AES_GF_H

#include <stdint.h>

#define AES_POLY 0x11B   // x^8 + x^4 + x^3 + x + 1

// ---------------------------------------------------------------------------
// gf_mul : Multiply two bytes in GF(2^8) mod AES_POLY
//   Uses shift-and-XOR (Russian peasant multiplication)
//   Equivalent to polynomial multiplication then reduction by 0x11B
// ---------------------------------------------------------------------------
inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t  result = 0;
    uint16_t tmp    = a;        // extended to avoid 8-bit overflow on shift
    while (b) {
        if (b & 1)
            result ^= (uint8_t)tmp;   // add (XOR) current term
        tmp <<= 1;
        if (tmp & 0x100)
            tmp ^= AES_POLY;          // reduce mod m(x) when degree hits 8
        b >>= 1;
    }
    return result;
}

// ---------------------------------------------------------------------------
// gf_pow : Compute a^n in GF(2^8) using square-and-multiply
// ---------------------------------------------------------------------------
inline uint8_t gf_pow(uint8_t a, int n) {
    uint8_t result = 1;
    while (n > 0) {
        if (n & 1)
            result = gf_mul(result, a);
        a = gf_mul(a, a);   // squaring — linear operation over GF(2)
        n >>= 1;
    }
    return result;
}

// ---------------------------------------------------------------------------
// gf_inv : Multiplicative inverse using Fermat's Little Theorem
//   a^{-1} = a^{254}   (special case: 0^{-1} = 0 by AES convention)
// ---------------------------------------------------------------------------
inline uint8_t gf_inv(uint8_t a) {
    return (a == 0) ? 0 : gf_pow(a, 254);
}

// ---------------------------------------------------------------------------
// affine_transform : Step 2 of AES S-box (linear over GF(2))
//
//   For each bit i:
//     s_i = b_i ^ b_{(i+4)%8} ^ b_{(i+5)%8} ^ b_{(i+6)%8} ^ b_{(i+7)%8} ^ c_i
//   where c = 0x63 (01100011 in binary)
//
//   This is the matrix equation:  s = A * b  XOR  0x63
//   A is the 8x8 circulant matrix from FIPS-197
// ---------------------------------------------------------------------------
inline uint8_t affine_transform(uint8_t b) {
    uint8_t s = 0;
    for (int i = 0; i < 8; i++) {
        int bit = ((b >>  i        ) & 1)
                ^ ((b >> ((i+4) % 8)) & 1)
                ^ ((b >> ((i+5) % 8)) & 1)
                ^ ((b >> ((i+6) % 8)) & 1)
                ^ ((b >> ((i+7) % 8)) & 1)
                ^ ((0x63 >> i       ) & 1);
        s |= (bit << i);
    }
    return s;
}

// ---------------------------------------------------------------------------
// inv_affine_transform : Inverse affine (for AES decryption)
//   For each bit i:
//     b_i = s_{(i+2)%8} ^ s_{(i+5)%8} ^ s_{(i+7)%8} ^ d_i
//   where d = 0x05
// ---------------------------------------------------------------------------
inline uint8_t inv_affine_transform(uint8_t s) {
    uint8_t b = 0;
    for (int i = 0; i < 8; i++) {
        int bit = ((s >> ((i+2) % 8)) & 1)
                ^ ((s >> ((i+5) % 8)) & 1)
                ^ ((s >> ((i+7) % 8)) & 1)
                ^ ((0x05 >> i       ) & 1);
        b |= (bit << i);
    }
    return b;
}

// ---------------------------------------------------------------------------
// sub_byte     : Full AES S-box on one byte  (replaces the 256-byte LUT)
// inv_sub_byte : Inverse S-box for decryption
// ---------------------------------------------------------------------------
inline uint8_t sub_byte(uint8_t a) {
    return affine_transform(gf_inv(a));
}

inline uint8_t inv_sub_byte(uint8_t a) {
    return gf_inv(inv_affine_transform(a));
}

#endif // AES_GF_H
