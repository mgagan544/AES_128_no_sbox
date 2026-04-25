#include <systemc.h>
#include "aes_core.h"
#include <cstdio>
#include <cstring>

// ── Helpers ──────────────────────────────────────────────────────────────────

static void print_sep() { printf("  %s\n","------------------------------------------------------------"); }

static void print_hex(const char* label, const uint8_t* d, int n) {
    printf("  %-18s: ", label);
    for (int i = 0; i < n; i++) printf("%02X ", d[i]);
    printf("\n");
}

static sc_biguint<128> bytes_to_u128(const uint8_t* b) {
    sc_biguint<128> v = 0;
    for (int i = 0; i < 16; i++)
        v = (v << 8) | (sc_biguint<128>)b[i];
    return v;
}

static void u128_to_bytes(sc_biguint<128> v, uint8_t* b) {
    for (int i = 0; i < 16; i++)
        b[i] = (uint8_t)((v >> (120 - 8*i)).to_uint() & 0xFF);
}

// ── NIST Test Vectors ─────────────────────────────────────────────────────────

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
static const int N_VECTORS = 3;

// ── Testbench ─────────────────────────────────────────────────────────────────

SC_MODULE(Testbench) {
    sc_out<bool>             clk_out, rst_out, start_out, mode_out;
    sc_out<sc_biguint<128>>  pt_out, key_out;
    sc_in<sc_biguint<128>>   ct_in;
    sc_in<bool>              done_in;

    int total_pass = 0, total_fail = 0;

    SC_CTOR(Testbench) { SC_THREAD(run); }

    void tick(int n = 1) {
        for (int i = 0; i < n; i++) {
            clk_out.write(true);  wait(5, SC_NS);
            clk_out.write(false); wait(5, SC_NS);
        }
    }

    void check(const char* label, bool ok) {
        printf("  %-48s : %s\n", label, ok ? "PASS ✓" : "FAIL ✗");
        ok ? total_pass++ : total_fail++;
    }

    void run() {
        // Reset
        rst_out.write(true); start_out.write(false);
        mode_out.write(false); pt_out.write(0); key_out.write(0);
        tick(3);
        rst_out.write(false); tick(1);

        printf("\n");
        printf("══════════════════════════════════════════════════════════\n");
        printf("   AES-128 SystemC Testbench  —  No S-Box Lookup Table   \n");
        printf("   SubBytes via GF(2^8) algebraic equations only         \n");
        printf("══════════════════════════════════════════════════════════\n\n");

        // ── Group 1: GF arithmetic ────────────────────────────────────────
        printf("┌─ [GROUP 1] GF(2^8) Arithmetic Unit Tests\n"); print_sep();
        check("gf_mul(0x57, 0x83) == 0xC1",        gf_mul(0x57,0x83)==0xC1);
        check("gf_mul(0x57, 0x02) == 0xAE",        gf_mul(0x57,0x02)==0xAE);
        check("gf_mul(0x53, gf_inv(0x53)) == 1",   gf_mul(0x53,gf_inv(0x53))==1);
        check("gf_mul(0xFF, gf_inv(0xFF)) == 1",   gf_mul(0xFF,gf_inv(0xFF))==1);
        check("gf_inv(0x00) == 0x00",              gf_inv(0x00)==0x00);
        printf("\n");

        // ── Group 2: S-Box ────────────────────────────────────────────────
        printf("┌─ [GROUP 2] S-Box Algebraic Unit Tests\n"); print_sep();
        struct { uint8_t in,exp; const char* lbl; } sb[]={
            {0x00,0x63,"sub_byte(0x00)==0x63"},
            {0x01,0x7c,"sub_byte(0x01)==0x7C"},
            {0x53,0xed,"sub_byte(0x53)==0xED"},
            {0xAB,0x62,"sub_byte(0xAB)==0x62"},
            {0xFF,0x16,"sub_byte(0xFF)==0x16"},
        };
        for (auto& x:sb) check(x.lbl, sub_byte(x.in)==x.exp);
        check("inv_sub_byte(sub_byte(0x53))==0x53", inv_sub_byte(sub_byte(0x53))==0x53);
        check("inv_sub_byte(sub_byte(0xFF))==0xFF", inv_sub_byte(sub_byte(0xFF))==0xFF);
        printf("\n");

        // ── Group 3: Encryption via DUT ───────────────────────────────────
        printf("┌─ [GROUP 3] NIST FIPS-197 Encryption Tests (SystemC DUT)\n"); print_sep();
        for (int t = 0; t < N_VECTORS; t++) {
            TestVector& v = VECTORS[t];
            printf("  [Test %d] %s\n", t+1, v.name);
            print_hex("Key",         v.key,         16);
            print_hex("Plaintext",   v.plaintext,   16);
            print_hex("Expected CT", v.expected_ct, 16);

            mode_out.write(false);
            pt_out.write(bytes_to_u128(v.plaintext));
            key_out.write(bytes_to_u128(v.key));
            start_out.write(true); tick(1);
            start_out.write(false); tick(2);

            uint8_t got[16];
            u128_to_bytes(ct_in.read(), got);
            print_hex("Got CT", got, 16);
            check("Ciphertext matches expected", memcmp(got, v.expected_ct, 16)==0);
            printf("\n"); tick(1);
        }

        // ── Group 4: Decryption ───────────────────────────────────────────
        printf("┌─ [GROUP 4] Decryption Roundtrip  decrypt(CT) == PT\n"); print_sep();
        for (int t = 0; t < N_VECTORS; t++) {
            TestVector& v = VECTORS[t];
            printf("  [Test %d] %s\n", t+1, v.name);
            print_hex("Ciphertext",  v.expected_ct, 16);
            print_hex("Expected PT", v.plaintext,   16);

            mode_out.write(true);
            pt_out.write(bytes_to_u128(v.expected_ct));
            key_out.write(bytes_to_u128(v.key));
            start_out.write(true); tick(1);
            start_out.write(false); tick(2);

            uint8_t got[16];
            u128_to_bytes(ct_in.read(), got);
            print_hex("Decrypted", got, 16);
            check("Decrypted matches plaintext", memcmp(got, v.plaintext, 16)==0);
            printf("\n"); tick(1);
        }

        // ── Group 5: Key Schedule ─────────────────────────────────────────
        printf("┌─ [GROUP 5] Key Schedule Spot Check\n"); print_sep();
        uint8_t ks[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        uint32_t w[44]; key_expansion(ks, w);
        check("W[4] == 0xa0fafe17", w[4]==0xa0fafe17);
        check("W[5] == 0x88542cb1", w[5]==0x88542cb1);
        check("W[6] == 0x23a33939", w[6]==0x23a33939);
        check("W[7] == 0x2a6c7605", w[7]==0x2a6c7605);
        printf("\n");

        // ── Summary ───────────────────────────────────────────────────────
        printf("══════════════════════════════════════════════════════════\n");
        printf("  RESULT : %d PASS  |  %d FAIL\n", total_pass, total_fail);
        printf("══════════════════════════════════════════════════════════\n\n");
        if (!total_fail) printf("  ✓ ALL TESTS PASSED\n\n");
        else             printf("  ✗ SOME TESTS FAILED\n\n");

        sc_stop();
    }
};

// ── sc_main ───────────────────────────────────────────────────────────────────

int sc_main(int argc, char* argv[]) {
    sc_signal<bool>              clk, rst, start, mode, done;
    sc_signal<sc_biguint<128>>   plaintext, key_sig, ciphertext;

    AES_Core dut("AES_Core");
    dut.clk(clk); dut.rst(rst); dut.start(start); dut.mode(mode);
    dut.plaintext(plaintext); dut.key_in(key_sig);
    dut.ciphertext(ciphertext); dut.done(done);

    Testbench tb("Testbench");
    tb.clk_out(clk); tb.rst_out(rst); tb.start_out(start); tb.mode_out(mode);
    tb.pt_out(plaintext); tb.key_out(key_sig);
    tb.ct_in(ciphertext); tb.done_in(done);

    // VCD waveform
    sc_trace_file* tf = sc_create_vcd_trace_file("aes_waveform");
    tf->set_time_unit(1, SC_NS);
    sc_trace(tf, clk,   "clk");
    sc_trace(tf, rst,   "rst");
    sc_trace(tf, start, "start");
    sc_trace(tf, mode,  "mode");
    sc_trace(tf, done,  "done");

    sc_start();
    sc_close_vcd_trace_file(tf);
    printf("  Waveform saved: aes_waveform.vcd  (view with: gtkwave aes_waveform.vcd)\n\n");
    return 0;
}
