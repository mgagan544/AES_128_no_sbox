# AES-128 SystemC — No S-Box Lookup Table

AES-128 encryption and decryption implemented in **SystemC 2.3.3**, where the SubBytes operation is computed entirely through **GF(2⁸) algebraic equations** — no precomputed lookup tables anywhere in the design.

> **22 PASS | 0 FAIL** — verified against NIST FIPS-197 official test vectors.

***

## Key Idea

Standard AES uses a hardcoded 256-byte S-box table. This implementation replaces it with:

$$
subByte(a)=affineTransform(a.pow(254) mod(x^8 +x^4 +x^3 +x+1))
$$

By **Fermat's Little Theorem** in GF(2⁸), every nonzero element satisfies $$a^{255} = 1$$, so $$a^{254} = a^{-1}$$. The inversion is computed using square-and-multiply (7 squarings + 6 multiplications) — no table, no memory access. Output is **bit-identical** to the FIPS-197 S-box.

***

## Project Structure

```
aes128-systemc-no-sbox/
├── aes_gf.h           # GF(2^8) arithmetic: gf_mul, gf_inv, affine_transform, sub_byte
├── aes_ops.h          # AES round operations: SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion
├── aes_core.h         # SystemC SC_MODULE — FSM, clock/reset ports, sc_biguint<128> interface
├── tb_aes.cpp         # Full SystemC testbench with VCD waveform trace (22 tests)
├── tb_standalone.cpp  # Same tests, zero SystemC dependency — compile and run instantly
├── Makefile           # Build rules for both modes
└── README.md
```

***

## File Descriptions

### `aes_gf.h` — Galois Field Arithmetic

The mathematical foundation. Every AES operation ultimately reduces to arithmetic in GF(2⁸) — the finite field with 256 elements, where each element is a byte treated as a polynomial over GF(2).

| Function | Description |
|---|---|
| `gf_mul(a, b)` | Multiply two bytes mod `0x11B` using shift-and-XOR |
| `gf_pow(a, n)` | Raise to power using square-and-multiply |
| `gf_inv(a)` | Compute `a^{-1}` = `a^254` (Fermat's theorem) |
| `affine_transform(b)` | 8-bit linear transform: `s_i = b_i ⊕ b_{i+4} ⊕ ... ⊕ c_i`, `c = 0x63` |
| `sub_byte(a)` | Full algebraic S-box: `affine_transform(gf_inv(a))` |
| `inv_sub_byte(a)` | Inverse S-box for decryption |

**Why `0x11B`?** It represents the irreducible polynomial $$x^8 + x^4 + x^3 + x + 1$$ over GF(2). After each multiplication, results are reduced modulo this polynomial to stay within 8 bits. It was chosen in FIPS-197 for its low Hamming weight and efficient hardware implementation.

### `aes_ops.h` — Round Operations

Implements all four AES round transformations operating on a 4×4 byte state matrix:

| Function | Purpose | Why needed |
|---|---|---|
| `sub_bytes()` | Apply `sub_byte()` to all 16 bytes | Only nonlinear step — provides confusion |
| `shift_rows()` | Cyclically shift rows 0–3 by 0–3 positions | Cross-column mixing setup |
| `mix_columns()` | MDS matrix multiply per column over GF(2⁸) | Diffusion — 1 byte change affects all 4 in column |
| `add_round_key()` | XOR state with round key | Key injection |
| `key_expansion()` | Expand 128-bit key into 44 round-key words | Derives 11 independent round keys |

### `aes_core.h` — SystemC Module

```
SC_MODULE(AES_Core) {
    sc_in<bool>              clk, rst, start, mode;  // mode: 0=encrypt, 1=decrypt
    sc_in<sc_biguint<128>>   plaintext, key_in;
    sc_out<sc_biguint<128>>  ciphertext;
    sc_out<bool>             done;
}
```

> **Note:** `sc_biguint<128>` is required — `sc_uint` is limited to 64 bits in SystemC 2.3.x.

**FSM states:**

```
[IDLE] --start=1--> [PROCESSING] --result ready--> [DONE_ST] --> [IDLE]
```

Latency: **2 clock cycles** from `start=1` to `done=1`.

### `tb_aes.cpp` — SystemC Testbench

Drives the `AES_Core` DUT through all 22 test cases and writes a **VCD waveform** (`aes_waveform.vcd`) for signal inspection in GTKWave.

### `tb_standalone.cpp` — Standalone Testbench

Identical test logic with no SystemC dependency. Useful for rapid verification of the algorithm without a full SystemC installation.

***

## Test Cases (22 total)

| Group | Count | What is tested |
|---|---|---|
| GF(2⁸) Arithmetic | 5 | `gf_mul`, `gf_inv`, special cases |
| S-Box Algebraic | 7 | `sub_byte` vs FIPS-197 expected values |
| NIST Encryption | 3 | FIPS-197 Appendix B, C, and all-zeros vector |
| Decryption Roundtrip | 3 | `decrypt(encrypt(pt)) == pt` for all 3 vectors |
| Key Schedule | 4 | Round-key words W[1]–W[2] vs FIPS-197 Appendix A |

***

## Build & Run

### Standalone (no dependencies)

```bash
g++ -std=c++17 -O2 tb_standalone.cpp -o aes_test && ./aes_test
```

### With SystemC

```bash
export SYSTEMC_HOME=/usr/local/systemc-2.3.3
export LD_LIBRARY_PATH=$SYSTEMC_HOME/lib-linux64:$LD_LIBRARY_PATH

g++ -std=c++17 -O2 \
    -I$SYSTEMC_HOME/include \
    -L$SYSTEMC_HOME/lib-linux64 \
    tb_aes.cpp -lsystemc -lm \
    -Wl,-rpath,$SYSTEMC_HOME/lib-linux64 \
    -o aes_sim && ./aes_sim
```

### View Waveform

```bash
sudo apt install gtkwave
gtkwave aes_waveform.vcd
```

Drag `clk`, `rst`, `start`, `done`, `plaintext`, `ciphertext` into the wave viewer. Set data format to **Hex** to read 128-bit values.

***

## Requirements

| Requirement | Version |
|---|---|
| g++ | ≥ 9.0 (C++17) |
| SystemC | 2.3.3 (Accellera) |
| GTKWave | Any (optional, for waveform) |
| OS | Ubuntu 20.04+ / any Linux |

***

## Mathematical Background

### Why Galois Fields?

AES needs arithmetic that:
- Stays within 1 byte (8 bits) — no overflow
- Is invertible — every nonzero element has a multiplicative inverse
- Maps to hardware efficiently — uses only XOR and shifts

GF(2⁸) satisfies all three. Addition = XOR. Multiplication = shift-and-XOR with polynomial reduction.

### Why the S-box is Nonlinear

The function $$f(a) = a^{-1}$$ is nonlinear because:
$$(a \oplus b)^{-1} \neq a^{-1} \oplus b^{-1}$$

No matrix equation over GF(2) can express this for all 256 inputs. This nonlinearity is what gives AES resistance to linear cryptanalysis.

### Security Equivalence

This table-free implementation preserves full AES security. The 256-byte lookup table in standard AES is a **performance optimization only** — a precomputed cache of $$a^{254}$$. Computing it live via `gf_pow(a, 254)` produces identical outputs and identical security properties.

***
