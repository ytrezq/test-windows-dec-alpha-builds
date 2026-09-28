#ifndef AXP64EMU_HELPERS_H
#define AXP64EMU_HELPERS_H
#include <stdint.h>
struct CPUAlpha;

/* Features reported as *implemented* by AMASK (EV67: BWX|FIX|CIX|MVI). */
#define ALPHA_AMASK_IMPL 0x107ULL

void helper_int_op(struct CPUAlpha *cpu, uint32_t insn);
void helper_fp_op (struct CPUAlpha *cpu, uint32_t insn);
void helper_fp_mem(struct CPUAlpha *cpu, uint32_t insn);
void helper_native (struct CPUAlpha *cpu, uint32_t insn);

#endif
