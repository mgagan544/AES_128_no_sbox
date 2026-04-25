// =============================================================================
// FILE        : tb_standalone.cpp
// DESCRIPTION : Standalone C++ testbench — identical logic, NO SystemC needed
//
//  COMPILE & RUN:
//    g++ -std=c++17 -O2 tb_standalone.cpp -o aes_test && ./aes_test
// =============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "aes_ops.h"   // includes aes_gf.h

static void print_hex(const char* label, const uint8_t* d, int n) {
    printf("  %-18s: ", label);
    for (int i = 0; i < n; i++) printf("%02X ", d[i]);
    printf("\n");
}
static void print_sep() { printf("  %s\n","------------------------------------------------------------"); }

int total_pass = 0, total_fail = 0;
void check(const char* label, bool ok) {
    printf("  %-45s : %s\n", label, ok ? "PASS ✓" : "FAIL ✗");
    ok ? total_pass++ : total_fail++;
}

struct TestVector {
    const char* name;
    uint8_t key[16], plaintext[16], expected_ct[16];
};

static TestVector VECTORS[] = {
    {"NIST FIPS-197 Appendix B",
     {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
     {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34},
     {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32}},
    {"All-zeros key & plaintext",
     {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
     {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
     {0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e}},
    {"NIST FIPS-197 Appendix C",
     {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
     {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
     {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a}}
};

int main() {
    printf("\n");
    printf("══════════════════════════════════════════════════════════\n");
    printf("   AES-128 Standalone Test  —  No S-Box Lookup Table     \n");
    printf("══════════════════════════════════════════════════════════\n\n");

    // Group 1: GF arithmetic
    printf("┌─ [GROUP 1] GF(2^8) Arithmetic\n"); print_sep();
    check("gf_mul(0x57,0x83)==0xC1",          gf_mul(0x57,0x83)==0xC1);
    check("gf_mul(0x57,0x02)==0xAE",          gf_mul(0x57,0x02)==0xAE);
    check("gf_mul(a,gf_inv(a))==1 [0x53]",    gf_mul(0x53,gf_inv(0x53))==1);
    check("gf_mul(a,gf_inv(a))==1 [0xFF]",    gf_mul(0xFF,gf_inv(0xFF))==1);
    check("gf_inv(0x00)==0x00",               gf_inv(0x00)==0x00);
    printf("\n");

    // Group 2: S-Box
    printf("┌─ [GROUP 2] S-Box Algebraic Unit Tests\n"); print_sep();
    struct { uint8_t in,exp; const char* lbl; } sb[]={
        {0x00,0x63,"sub_byte(0x00)==0x63"},
        {0x01,0x7c,"sub_byte(0x01)==0x7C"},
        {0x53,0xed,"sub_byte(0x53)==0xED"},
        {0xAB,0x62,"sub_byte(0xAB)==0x62"},
        {0xFF,0x16,"sub_byte(0xFF)==0x16"},
        {0xF3,0xCA,"sub_byte(0xF3)==0xCA"},
        {0x8A,0x7E,"sub_byte(0x8A)==0x7E"},
    };
    for (auto& x:sb) check(x.lbl, sub_byte(x.in)==x.exp);
    check("inv_sub_byte(sub_byte(0x53))==0x53", inv_sub_byte(sub_byte(0x53))==0x53);
    check("inv_sub_byte(sub_byte(0xFF))==0xFF", inv_sub_byte(sub_byte(0xFF))==0xFF);
    printf("\n");

    // Group 3: Encryption
    printf("┌─ [GROUP 3] NIST Encryption Tests\n"); print_sep();
    for (int t=0;t<3;t++) {
        uint8_t out[16];
        printf("  [Test %d] %s\n",t+1,VECTORS[t].name);
        print_hex("Key",        VECTORS[t].key,        16);
        print_hex("Plaintext",  VECTORS[t].plaintext,  16);
        print_hex("Expected CT",VECTORS[t].expected_ct,16);
        aes128_encrypt(VECTORS[t].plaintext,VECTORS[t].key,out);
        print_hex("Got CT",     out,                   16);
        check("Ciphertext matches", memcmp(out,VECTORS[t].expected_ct,16)==0);
        printf("\n");
    }

    // Group 4: Decryption
    printf("┌─ [GROUP 4] Decryption Roundtrip\n"); print_sep();
    for (int t=0;t<3;t++) {
        uint8_t out[16];
        printf("  [Test %d] %s\n",t+1,VECTORS[t].name);
        print_hex("Ciphertext", VECTORS[t].expected_ct,16);
        aes128_decrypt(VECTORS[t].expected_ct,VECTORS[t].key,out);
        print_hex("Decrypted",  out,                   16);
        print_hex("Expected PT",VECTORS[t].plaintext,  16);
        check("Decrypted matches plaintext", memcmp(out,VECTORS[t].plaintext,16)==0);
        printf("\n");
    }

    // Group 5: Key Schedule
    printf("┌─ [GROUP 5] Key Schedule Spot Check\n"); print_sep();
    uint8_t ks[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint32_t w[44]; key_expansion(ks,w);
    check("W[4]==0xa0fafe17", w[4]==0xa0fafe17);
    check("W[5]==0x88542cb1", w[5]==0x88542cb1);
    check("W[6]==0x23a33939", w[6]==0x23a33939);
    check("W[7]==0x2a6c7605", w[7]==0x2a6c7605);
    printf("\n");

    printf("══════════════════════════════════════════════════════════\n");
    printf("  RESULT : %d PASS  |  %d FAIL\n", total_pass, total_fail);
    printf("══════════════════════════════════════════════════════════\n\n");
    if (!total_fail) printf("  ✓ ALL TESTS PASSED\n\n");
    return total_fail;
}
