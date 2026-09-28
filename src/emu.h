/* axp64emu - DEC Alpha (AXP64) user-mode dynamic translator
 *
 * Guest memory is mapped IDENTITY (host VA == guest VA), which is possible
 * because the emulator itself is PIE and loads high, leaving the classic
 * Windows image bases (0x400000, 0x8370000, 0x180000000) free.  A guest
 * load/store therefore becomes a direct x86-64 memory access.
 */
#ifndef AXP64EMU_EMU_H
#define AXP64EMU_EMU_H

#include <stdint.h>
#include <stddef.h>

/* ---- Guest CPU state -------------------------------------------------- */
/* Offsets are baked into generated code; keep this layout stable. */
typedef struct CPUAlpha {
    uint64_t ireg[32];   /* 0x000 : r0..r31 (r31 always reads 0)          */
    uint64_t freg[32];   /* 0x100 : f0..f31 (f31 always reads 0), raw bits */
    uint64_t pc;         /* 0x200 */
    uint64_t fpcr;       /* 0x208 */
    uint64_t exit_code;  /* 0x210 : why we left generated code           */
    uint64_t scratch0;   /* 0x218 */
    uint64_t scratch1;   /* 0x220 */
    uint64_t icount;     /* 0x228 */
    uint64_t ret_pc;     /* where the call gate resumes after a native call */
} CPUAlpha;

#define OFF_IREG(n)  ((int32_t)(offsetof(CPUAlpha, ireg) + 8*(n)))
#define OFF_FREG(n)  ((int32_t)(offsetof(CPUAlpha, freg) + 8*(n)))
#define OFF_PC       ((int32_t)offsetof(CPUAlpha, pc))
#define OFF_FPCR     ((int32_t)offsetof(CPUAlpha, fpcr))
#define OFF_EXIT     ((int32_t)offsetof(CPUAlpha, exit_code))
#define OFF_SCR0     ((int32_t)offsetof(CPUAlpha, scratch0))
#define OFF_SCR1     ((int32_t)offsetof(CPUAlpha, scratch1))
#define OFF_RETPC    ((int32_t)offsetof(CPUAlpha, ret_pc))

/* exit_code values */
enum {
    EXIT_BLOCK_END = 0,  /* normal: pc holds next address        */
    EXIT_UNIMPL    = 1,  /* undecodable instruction, pc holds it */
    EXIT_HALT      = 2,
    EXIT_CALLOUT   = 3,  /* guest called a native (host) routine */
};

/* ---- Translation cache ------------------------------------------------ */
typedef struct TBlock {
    uint64_t        guest_pc;
    uint8_t        *code;        /* host entry point                     */
    struct TBlock  *hash_next;
    /* chaining: sites inside `code` holding a rel32 to be back-patched   */
    uint32_t       *patch_site[2];
    uint64_t        patch_target[2];
    int             npatch;
    int             ninsn;
} TBlock;

typedef struct JitCtx {
    uint8_t  *cache;          /* RWX code cache        */
    size_t    cache_size;
    uint8_t  *cache_ptr;
    TBlock  **hash;
    size_t    hash_size;
    TBlock   *blocks;
    size_t    nblocks, max_blocks;
    uint8_t  *epilogue;       /* shared return-to-dispatcher stub */
    int       trace;
    uint64_t  xlat_lo, xlat_hi; /* addresses the translator may read from */
} JitCtx;

typedef void (*BlockFn)(CPUAlpha *cpu);

int      jit_init(JitCtx *j, size_t cache_bytes, size_t max_blocks);
TBlock  *jit_lookup(JitCtx *j, uint64_t pc);
TBlock  *jit_translate(JitCtx *j, CPUAlpha *cpu, uint64_t pc);
void     jit_run(JitCtx *j, CPUAlpha *cpu, uint64_t stop_lo, uint64_t stop_hi,
                 uint64_t max_insn);
/* Run until the guest returns to `stop_pc` (used by the PE loader). */
void     jit_run_until(JitCtx *j, CPUAlpha *cpu, uint64_t stop_pc, uint64_t max_insn);

/* Memory helpers */
void    *guest_map(uint64_t addr, size_t len, int prot);

#endif
