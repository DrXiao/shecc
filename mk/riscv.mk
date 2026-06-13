# Enforce the use qemu of by setting the ALLOW_MACHINES variable to empty
ALLOW_MACHINES = Scaleway-EM-RV1-C4M16S128-A
ARCH_RUNNER = qemu-riscv32
ARCH_DEFS = \
    "/* target: RISCV */\n$\
    \#pragma once\n$\
    \#define ARCH_PREDEFINED \"__riscv\" /* Older versions of the GCC toolchain defined __riscv__ */\n$\
    \#define ELF_MACHINE 0xf3\n$\
    \#define ELF_FLAGS 0\n$\
    \#define DYN_LINKER \"/lib/ld-linux-riscv32-ilp32d.so.1\"\n$\
    \#define LIBC_SO \"libc.so.6\"\n$\
    \#define PLT_FIXUP_SIZE 32\n$\
    \#define PLT_ENT_SIZE 16\n$\
    \#define RESERVED_GOT_NUM 2\n$\
    \#define R_ARCH_JUMP_SLOT 0x5\n$\
    \#define MAX_ARGS_IN_REG 8\n$\
    "
# If the running machine has the "fastfetch" tool installed, the build
# system will verify whether native execution can be performed.
ifneq ($(shell which fastfetch),)
    # 1. Replace whitespaces with hyphens after retrieving the host
    #    machine name via the "fastfetch" tool.
    #
    # 2. If at least one machine name in the allowlist is found in
    #    the host machine name, it can perform native execution.
    #
    #    Therefore, set USE_QEMU to 0.
    HOST_MACHINE = $(shell fastfetch --logo none --structure Host | sed 's/ /-/g')
    USE_QEMU = $(if $(strip $(foreach MACHINE, $(ALLOW_MACHINES), $(findstring $(MACHINE),$(HOST_MACHINE)))),0,1)
endif

TOOLCHAIN_CANDIDATES = riscv32-unknown-linux-gnu-
