#ifndef AES_CORE_H
#define AES_CORE_H

#include <systemc.h>
#include "aes_ops.h"

typedef enum { IDLE, PROCESSING, DONE_ST } AES_FSM;

SC_MODULE(AES_Core) {

    sc_in<bool>              clk;
    sc_in<bool>              rst;
    sc_in<bool>              start;
    sc_in<bool>              mode;          // 0=encrypt, 1=decrypt
    sc_in<sc_biguint<128>>   plaintext;
    sc_in<sc_biguint<128>>   key_in;
    sc_out<sc_biguint<128>>  ciphertext;
    sc_out<bool>             done;

    sc_signal<AES_FSM>          state;
    sc_signal<sc_biguint<128>>  result_reg;
    sc_signal<bool>             done_reg;

    SC_CTOR(AES_Core) {
        SC_METHOD(fsm_process);
        sensitive << clk.pos();
        dont_initialize();

        SC_METHOD(output_logic);
        sensitive << result_reg << done_reg;
        dont_initialize();
    }

    void fsm_process() {
        if (rst.read()) {
            state.write(IDLE);
            result_reg.write(0);
            done_reg.write(false);
            return;
        }
        switch (state.read()) {
            case IDLE:
                done_reg.write(false);
                if (start.read()) state.write(PROCESSING);
                break;

            case PROCESSING: {
                sc_biguint<128> in_val  = plaintext.read();
                sc_biguint<128> key_val = key_in.read();

                uint8_t in_b[16], key_b[16], out_b[16];
                for (int i = 0; i < 16; i++) {
                    in_b[i]  = (uint8_t)((in_val  >> (120 - 8*i)).to_uint() & 0xFF);
                    key_b[i] = (uint8_t)((key_val >> (120 - 8*i)).to_uint() & 0xFF);
                }

                if (mode.read() == 0)
                    aes128_encrypt(in_b, key_b, out_b);
                else
                    aes128_decrypt(in_b, key_b, out_b);

                sc_biguint<128> result = 0;
                for (int i = 0; i < 16; i++)
                    result = (result << 8) | (sc_biguint<128>)out_b[i];

                result_reg.write(result);
                done_reg.write(true);
                state.write(DONE_ST);
                break;
            }
            case DONE_ST:
                done_reg.write(false);
                state.write(IDLE);
                break;
        }
    }

    void output_logic() {
        ciphertext.write(result_reg.read());
        done.write(done_reg.read());
    }
};

#endif // AES_CORE_H
