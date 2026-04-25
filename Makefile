# =============================================================================
# Makefile — AES-128 No S-Box SystemC Project
#
# TARGETS:
#   make standalone   — build & run without SystemC (recommended first step)
#   make sim          — build & run with SystemC (requires SYSTEMC_HOME set)
#   make clean        — remove binaries and VCD files
#
# USAGE:
#   Quick test (no SystemC):
#     make standalone
#
#   With SystemC installed:
#     export SYSTEMC_HOME=/path/to/systemc-2.3.x
#     make sim
# =============================================================================

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wno-unused-result

# ── Standalone (no SystemC) ─────────────────────────────────────────────────
standalone: tb_standalone.cpp aes_ops.h aes_gf.h
	$(CXX) $(CXXFLAGS) tb_standalone.cpp -o aes_test
	@echo ""
	@./aes_test

# ── SystemC simulation ───────────────────────────────────────────────────────
ifndef SYSTEMC_HOME
sim:
	@echo "ERROR: SYSTEMC_HOME not set. Export it first:"
	@echo "  export SYSTEMC_HOME=/path/to/systemc"
	@exit 1
else
SYSC_INC := $(SYSTEMC_HOME)/include
SYSC_LIB := $(SYSTEMC_HOME)/lib-linux64

sim: tb_aes.cpp aes_core.h aes_ops.h aes_gf.h
	$(CXX) $(CXXFLAGS) -I$(SYSC_INC) -L$(SYSC_LIB) tb_aes.cpp \
	    -lsystemc -lm -Wl,-rpath,$(SYSC_LIB) -o aes_sim
	@echo ""
	@./aes_sim
endif

clean:
	rm -f aes_test aes_sim *.vcd

.PHONY: standalone sim clean
