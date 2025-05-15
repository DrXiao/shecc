ARCH_EXEC = qemu-riscv32
TARGET_EXEC := $(shell which $(TARGET_EXEC))

export TARGET_EXEC

riscv-specific-defs = \
    $(Q)$(PRINTF) \
        "/* target: RISCV */\n$\
        \#pragma once\n$\
        \#define ARCH_PREDEFINED \"__riscv\" /* Older versions of the GCC toolchain defined __riscv__ */\n$\
        \#define ELF_MACHINE 0xf3\n$\
        \#define ELF_FLAGS 0\n$\
        "
