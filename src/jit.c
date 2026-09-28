/* Alpha AXP -> x86-64 basic-block translator. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
static void *rwx_alloc(size_t n)
{ return VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); }
#else
#include <sys/mman.h>
static void *rwx_alloc(size_t n)
{
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}
#endif
#include "emu.h"
#include "x86emit.h"
#include "helpers.h"

#include <cpuid.h>

/* scratch host registers used by the translator */
#define TA RAX
#define TB RCX          /* also the shift count register (CL) */
#define TC RDX
#define TD RSI
#define TE RDI
/* R8..R11 are caller-saved in both host ABIs, so the wider bit-manipulation
 * sequences (the S<->T format expansion, CVTTQ) use them as extra scratch. */

/* Host features probed once; the SSE4.1 packed min/max have SSE2 fallbacks. */
static int      g_has_sse41;
static uint64_t g_zap_mask[256];      /* byte-enable -> 64-bit mask         */

/* MXCSR images for the four Alpha rounding modes.  All exceptions are
 * masked and flush-to-zero is on: Alpha delivers a true zero when a result
 * underflows and the trap is disabled, which is exactly what FTZ does.
 *   0 = /C chopped -> toward zero (11)     1 = /M -> -inf   (01)
 *   2 = normal     -> nearest     (00)     3 = FPCR value 3 -> +inf (10)  */
static const uint32_t g_mxcsr_tab[4] = {
    0x9F80u | 0x6000u, 0x9F80u | 0x2000u, 0x9F80u | 0x0000u, 0x9F80u | 0x4000u
};

/* Per-block MXCSR bookkeeping (translation is single threaded). */
static uint8_t *g_mx_slot;     /* prologue stmxcsr, nop'd out when unused   */
static int      g_fp_used;     /* this block reprogrammed MXCSR             */
static int      g_cur_mode;    /* -1 host mode, -2 unknown, 0..3 Alpha rnd  */

static inline void test_ri(Asm *a, int r, int32_t imm)
{ rexw(a, 0, r); ab(a, 0xF7); modrm_rr(a, 0, r); ad(a, (uint32_t)imm); }
static inline void call_r(Asm *a, int r)
{ if (r >= R8) ab(a, 0x41); ab(a, 0xFF); modrm_rr(a, 2, r); }
static inline void mov_r32_imm(Asm *a, int dst, uint32_t v)
{ rex0(a, 0, dst); ab(a, (uint8_t)(0xB8 | (dst & 7))); ad(a, v); }

/* ---- guest register access ------------------------------------------- */
static void ld_ireg(Asm *a, int dst, int r)
{ if (r == 31) mov_r_imm64(a, dst, 0); else ld_cpu(a, dst, OFF_IREG(r)); }
static void st_ireg(Asm *a, int r, int src)
{ if (r != 31) st_cpu(a, OFF_IREG(r), src); }
static void ld_freg(Asm *a, int dst, int r)
{ if (r == 31) mov_r_imm64(a, dst, 0); else ld_cpu(a, dst, OFF_FREG(r)); }
static void st_freg(Asm *a, int r, int src)
{ if (r != 31) st_cpu(a, OFF_FREG(r), src); }
/* operand B of the operate format: register or 8-bit zero-extended literal */
static void ld_opb(Asm *a, int dst, int rb, int islit, int lit)
{ if (islit) mov_r_imm64(a, dst, (uint64_t)(unsigned)lit); else ld_ireg(a, dst, rb); }

/* ---- block frame ----------------------------------------------------- *
 * A translated block is a C-callable function `void blk(CPUAlpha*)`.  The
 * two host ABIs differ, so the frame is per-target:
 *   SysV : arg0 in rdi; rsi/rdi are scratch; no shadow space -> just rbp.
 *   Win64: arg0 in rcx; rsi/rdi are nonvolatile (we use them as scratch, so
 *          we must save them); every call needs 32 bytes of shadow space at
 *          16-byte alignment, reserved once for the whole block.
 * Entry rsp ≡ 8 (mod 16).  Win64: 3 pushes -> ≡0, then sub 32 -> ≡0, so a
 * `call` lands with rsp ≡ 0 as required. */
/* Two 8-byte scratch slots live above the (Win64) shadow area: one holds the
 * host MXCSR while the block runs with the Alpha rounding mode, the other
 * stages a value for ldmxcsr.  Entry rsp == 8 (mod 16); the extra frame is a
 * multiple of 16 so a call still lands with rsp == 0 (mod 16). */
#ifdef _WIN32
#  define FRAME_EXTRA 48              /* 32 bytes of shadow space + 16 ours */
#  define MXSAVE_OFF  32
#  define MXTMP_OFF   40
#else
#  define FRAME_EXTRA 16
#  define MXSAVE_OFF  0
#  define MXTMP_OFF   8
#endif

static void emit_frame_enter(Asm *a)
{
#ifdef _WIN32
    push_r(a, RBP); push_r(a, RSI); push_r(a, RDI);
    mov_r_r(a, RBP, RCX);
#else
    push_r(a, RBP);
    mov_r_r(a, RBP, RDI);
#endif
    alu_ri(a, D_SUB, RSP, FRAME_EXTRA);
    g_mx_slot  = a->p;                /* patched to a nop if no FP is used */
    stmxcsr_m(a, RSP, MXSAVE_OFF);
    g_fp_used  = 0;
    g_cur_mode = -1;
}
static void emit_frame_leave(Asm *a)
{
    if (g_fp_used) ldmxcsr_m(a, RSP, MXSAVE_OFF);
    alu_ri(a, D_ADD, RSP, FRAME_EXTRA);
#ifdef _WIN32
    pop_r(a, RDI); pop_r(a, RSI); pop_r(a, RBP);
#else
    pop_r(a, RBP);
#endif
}

/* ---- helper call: void h(CPUAlpha *cpu, uint32_t insn) ---------------- */
static void emit_helper(Asm *a, void *fn, uint32_t insn)
{
    /* native code must never see our rounding mode / flush-to-zero */
    if (g_fp_used && g_cur_mode != -1) {
        ldmxcsr_m(a, RSP, MXSAVE_OFF);
        g_cur_mode = -1;
    }
#ifdef _WIN32
    mov_r_r(a, RCX, CPUREG);        /* Win64 arg0 = rcx; shadow already set */
    mov_r32_imm(a, RDX, insn);
#else
    mov_r_r(a, RDI, CPUREG);
    mov_r32_imm(a, RSI, insn);
#endif
    mov_r_imm64(a, RAX, (uint64_t)fn);
    call_r(a, RAX);
}

/* ---- block exit ------------------------------------------------------- */
static void emit_exit(Asm *a, uint64_t next_pc, uint64_t exit_code)
{
    mov_r_imm64(a, TA, next_pc);
    st_cpu(a, OFF_PC, TA);
    if (exit_code) { mov_r_imm64(a, TA, exit_code); st_cpu(a, OFF_EXIT, TA); }
    emit_frame_leave(a);
    ret_(a);
}

/* ====================================================================== *
 *  Hardware SIMD / floating point
 *
 *  Every Alpha multimedia (MVI) instruction and the entire floating-point
 *  set below is emitted as real x86-64 SSE code.  Nothing here calls back
 *  into C: the C helpers remain only as the safety net for encodings the
 *  translator does not recognise.
 * ====================================================================== */

/* zero-extend a 32-bit value already sitting in a 64-bit register */
static void zext32(Asm *a, int r) { alu32_rr(a, X_OR, r, r); }

/* FP register file <-> xmm */
static void ld_fx(Asm *a, int x, int r)
{ if (r == 31) pxor_x_x(a, x, x); else movq_x_m(a, x, CPUREG, OFF_FREG(r)); }
static void st_fx(Asm *a, int r, int x)
{ if (r != 31) movq_m_x(a, CPUREG, OFF_FREG(r), x); }

/* Program the host rounding mode from the instruction's qualifier.  The
 * value is only reloaded when it actually changes inside the block, and the
 * host's own MXCSR is put back before any exit or call out to C. */
static void emit_set_round(Asm *a, int rnd)
{
    g_fp_used = 1;
    if (rnd == 3) {                       /* /D : dynamic, from FPCR<59:58> */
        ld_cpu(a, TA, OFF_FPCR);
        shift_imm(a, S_SHR, TA, 58);
        alu_ri(a, D_AND, TA, 3);
        mov_r_imm64(a, TB, (uint64_t)(uintptr_t)g_mxcsr_tab);
        lea_isd(a, TB, TB, TA, 4, 0);
        ldlu_via(a, TA, TB, 0);
        stl_via(a, RSP, MXTMP_OFF, TA);
        ldmxcsr_m(a, RSP, MXTMP_OFF);
        g_cur_mode = -2;
        return;
    }
    if (g_cur_mode == rnd) return;
    mov_r32_imm(a, TA, g_mxcsr_tab[rnd]);
    stl_via(a, RSP, MXTMP_OFF, TA);
    ldmxcsr_m(a, RSP, MXTMP_OFF);
    g_cur_mode = rnd;
}

/* dst = {Fb<63:62>, Fb<58:29>} : the S-format single hidden in a T register.
 * The expanded exponent bits <61:59> are redundant and dropped.  Clobbers R8. */
static void emit_t_to_s(Asm *a, int dst, int src)
{
    mov_r_r(a, R8, src);
    shift_imm(a, S_SHR, R8, 62);
    shift_imm(a, S_SHL, R8, 30);
    if (dst != src) mov_r_r(a, dst, src);
    shift_imm(a, S_SHR, dst, 29);
    alu_ri(a, D_AND, dst, 0x3FFFFFFF);
    alu_rr(a, X_OR, dst, R8);
}

/* dst = T-format image of the single in src (src must be zero-extended).
 * The architectural {e<7>,~e<7>x3,e<6:0>} replication is a rebias by 896 for
 * normals; zero/denormal and Inf/NaN are the two special cases.
 * Clobbers R8..R11 and TE; dst must be none of them. */
static void emit_s_to_t(Asm *a, int dst, int src)
{
    mov_r_r(a, R8, src);  shift_imm(a, S_SHR, R8, 31); shift_imm(a, S_SHL, R8, 63);
    mov_r_r(a, R9, src);  shift_imm(a, S_SHR, R9, 23); alu_ri(a, D_AND, R9, 0xFF);
    mov_r_r(a, R10, src); alu_ri(a, D_AND, R10, 0x7FFFFF); shift_imm(a, S_SHL, R10, 29);
    mov_r_r(a, R11, R9);  alu_ri(a, D_ADD, R11, 896);
    mov_r_imm64(a, TE, 0x7FF);
    cmp_ri(a, R9, 0xFF);
    cmov_rr(a, CC_E, R11, TE);            /* Inf / NaN saturate the exponent */
    mov_r_imm64(a, TE, 0);
    test_rr(a, R9, R9);
    cmov_rr(a, CC_E, R11, TE);            /* zero / S denormal: exponent 0,
                                           * the mantissa is kept as is     */
    shift_imm(a, S_SHL, R11, 52);
    mov_r_r(a, dst, R8);
    alu_rr(a, X_OR, dst, R11);
    alu_rr(a, X_OR, dst, R10);
}

/* ---------------------------------------------------------------------- *
 *  NaN result selection
 *
 *  x86 and Alpha disagree about which NaN an operation delivers:
 *    - a NaN the operation itself produced is the canonical POSITIVE quiet
 *      NaN on Alpha, the negative "indefinite" one on x86;
 *    - with two NaN operands x86 always keeps the first, while Alpha (and
 *      qemu, verified against qemu-alpha) applies the x87 rule: an SNaN
 *      loses to a QNaN, and otherwise the larger significand wins, ties
 *      going to the positive one.
 *  The common case is that the result is not a NaN at all, so the whole
 *  thing hangs off a single ucomis + jnp; the correction itself lives in a
 *  shared stub generated once into the code cache.
 * ---------------------------------------------------------------------- */
static uint8_t *g_nan_stub[2];        /* [0] = single, [1] = double        */

/* In: TA = the a operand's bits, TB = the b operand's bits (for a unary
 * operation both are the same).  Out: TA = the NaN Alpha would deliver.
 * Clobbers TA, TB, TC, R8, R9, R10 only, so the caller keeps every xmm. */
static void emit_nan_stub(Asm *a, int dbl)
{
    const uint64_t inf2  = dbl ? 0xFFE0000000000000ULL : 0xFF000000ULL;
    const uint64_t qbit  = dbl ? (1ULL << 51)          : (1ULL << 22);
    const uint64_t fracm = dbl ? 0x000FFFFFFFFFFFFFULL : 0x7FFFFFULL;
    const uint64_t canon = dbl ? 0x7FF8000000000000ULL : 0x7FC00000ULL;
    const int      sh    = dbl ? 63 : 31;
    uint32_t *to_bnan, *to_sil_a[3], *to_sil_b[3], *to_key;
    uint8_t  *l_sil_a, *l_sil_b, *l_key;
    int na = 0, nb = 0;

    /* |x| > +Inf  <=>  x is a NaN */
    mov_r_r(a, R8, TA); mov_r_r(a, R9, TB);
    if (dbl) { shift_imm(a, S_SHL, R8, 1); shift_imm(a, S_SHL, R9, 1); }
    else     { shift32_imm(a, S_SHL, R8, 1); shift32_imm(a, S_SHL, R9, 1); }
    mov_r_imm64(a, TC, inf2);
    alu_rr(a, X_CMP, R9, TC);
    to_bnan = jcc_rel32(a, CC_A);
    alu_rr(a, X_CMP, R8, TC);
    to_sil_a[na++] = jcc_rel32(a, CC_A);
    mov_r_imm64(a, TA, canon);            /* neither operand is a NaN      */
    ret_(a);

    l_sil_a = a->p;                       /* deliver a, quieted            */
    mov_r_imm64(a, TC, qbit);
    alu_rr(a, X_OR, TA, TC);
    ret_(a);

    l_sil_b = a->p;                       /* deliver b, quieted            */
    mov_r_r(a, TA, TB);
    mov_r_imm64(a, TC, qbit);
    alu_rr(a, X_OR, TA, TC);
    ret_(a);

    /* Control only reaches here by the jump above, where TC still holds
     * inf2 (the code laid out in between always returns). */
    patch_rel32(to_bnan, a->p);           /* b is a NaN                    */
    alu_rr(a, X_CMP, R8, TC);
    to_sil_b[nb++] = jcc_rel32(a, CC_BE); /* only b is a NaN               */
    mov_r_imm64(a, TC, qbit);
    mov_r_r(a, R8, TA); alu_rr(a, X_AND, R8, TC);   /* a is quiet?         */
    mov_r_r(a, R9, TB); alu_rr(a, X_AND, R9, TC);   /* b is quiet?         */
    test_rr(a, R8, R8);
    uint32_t *a_quiet = jcc_rel32(a, CC_NE);
    test_rr(a, R9, R9);                   /* a is an SNaN                  */
    to_sil_b[nb++] = jcc_rel32(a, CC_NE); /* b is a QNaN -> b wins         */
    to_key = jmp_rel32(a);                /* both SNaN -> compare          */
    patch_rel32(a_quiet, a->p);
    test_rr(a, R9, R9);                   /* a is a QNaN                   */
    to_sil_a[na++] = jcc_rel32(a, CC_E);  /* b is an SNaN -> a wins        */

    l_key = a->p;                         /* same class: larger significand,
                                           * ties to the positive operand  */
    patch_rel32(to_key, l_key);
    mov_r_imm64(a, TC, fracm);
    mov_r_r(a, R8, TA); alu_rr(a, X_AND, R8, TC); shift_imm(a, S_SHL, R8, 1);
    mov_r_r(a, R10, TA); shift_imm(a, S_SHR, R10, sh);
    alu_ri(a, D_XOR, R10, 1); alu_rr(a, X_OR, R8, R10);
    mov_r_r(a, R9, TB); alu_rr(a, X_AND, R9, TC); shift_imm(a, S_SHL, R9, 1);
    mov_r_r(a, R10, TB); shift_imm(a, S_SHR, R10, sh);
    alu_ri(a, D_XOR, R10, 1); alu_rr(a, X_OR, R9, R10);
    alu_rr(a, X_CMP, R8, R9);
    to_sil_a[na++] = jcc_rel32(a, CC_A);
    to_sil_b[nb++] = jmp_rel32(a);

    for (int i = 0; i < na; i++) patch_rel32(to_sil_a[i], l_sil_a);
    for (int i = 0; i < nb; i++) patch_rel32(to_sil_b[i], l_sil_b);
}

/* Emit the guard around an operation whose result is in `xres`, with the
 * operand bit patterns still live in `xa` and `xb`. */
static void emit_nanfix(Asm *a, int dbl, int xres, int xa, int xb)
{
    if (dbl) ucomisd_x(a, xres, xres); else ucomiss_x(a, xres, xres);
    uint32_t *fine = jcc_rel32(a, CC_NP);      /* not a NaN: nothing to do */
    if (dbl) { movq_r_x(a, TA, xa); movq_r_x(a, TB, xb); }
    else     { movd_r_x(a, TA, xa); movd_r_x(a, TB, xb); }
    mov_r_imm64(a, R11, (uint64_t)(uintptr_t)g_nan_stub[dbl ? 1 : 0]);
    call_r(a, R11);
    if (dbl) movq_x_r(a, xres, TA); else movd_x_r(a, xres, TA);
    patch_rel32(fine, a->p);
}

/* CVTTQ : round with the current mode, then take the result modulo 2^64.
 * cvtsd2si covers everything in range; the rare out-of-range, NaN and Inf
 * cases are rebuilt from the raw bit pattern, still without leaving the
 * generated code. */
static void emit_cvttq(Asm *a, int fb, int fc, int rnd)
{
    emit_set_round(a, rnd);
    ld_fx(a, X0, fb);
    cvtsd2si(a, TA, X0);
    mov_r_imm64(a, TB, 0x8000000000000000ULL);
    alu_rr(a, X_CMP, TA, TB);
    uint32_t *ok = jcc_rel32(a, CC_NE);

    movq_r_x(a, TC, X0);                  /* raw bits                       */
    mov_r_r(a, TD, TC);
    shift_imm(a, S_SHR, TD, 52);
    alu_ri(a, D_AND, TD, 0x7FF);
    mov_r_imm64(a, TA, 0);                /* NaN, Inf and |v| < 1 give 0    */
    cmp_ri(a, TD, 0x7FF);
    uint32_t *d1 = jcc_rel32(a, CC_E);
    test_rr(a, TD, TD);
    uint32_t *d2 = jcc_rel32(a, CC_E);
    mov_r_r(a, R8, TC);
    mov_r_imm64(a, R9, 0x000FFFFFFFFFFFFFULL);
    alu_rr(a, X_AND, R8, R9);
    mov_r_imm64(a, R9, 1ULL << 52);
    alu_rr(a, X_OR, R8, R9);              /* mantissa with the hidden bit   */
    alu_ri(a, D_SUB, TD, 1075);           /* >= 0 on this path              */
    mov_r_r(a, TB, TD);
    shift_cl(a, S_SHL, R8);
    mov_r_imm64(a, R9, 0);
    cmp_ri(a, TD, 64);
    cmov_rr(a, CC_AE, R8, R9);            /* shifted out entirely           */
    test_rr(a, TC, TC);
    uint32_t *pos = jcc_rel32(a, CC_NS);
    neg_r(a, R8);
    patch_rel32(pos, a->p);
    mov_r_r(a, TA, R8);

    patch_rel32(d1, a->p);
    patch_rel32(d2, a->p);
    patch_rel32(ok, a->p);
    st_freg(a, fc, TA);
}

/* ---- the multimedia extension (opcode 0x1C) --------------------------- */
/* MINxx / MAXxx: one SSE instruction where SSE4.1 is available, an SSE2
 * sequence otherwise.  Operands arrive in X0 (Ra) and X1 (Rb); the result
 * is left in X0. */
static void emit_mvi_minmax(Asm *a, int func)
{
    switch (func) {
    case 0x39: pminsw(a, X0, X1); return;                      /* MINSW4 */
    case 0x3A: pminub(a, X0, X1); return;                      /* MINUB8 */
    case 0x3C: pmaxub(a, X0, X1); return;                      /* MAXUB8 */
    case 0x3F: pmaxsw(a, X0, X1); return;                      /* MAXSW4 */
    case 0x38:                                                 /* MINSB8 */
        if (g_has_sse41) { pminsb(a, X0, X1); return; }
        mov_r_imm64(a, TC, 0x8080808080808080ULL); movq_x_r(a, X2, TC);
        sse_rr(a, 0x66, 0xEF, X0, X2); sse_rr(a, 0x66, 0xEF, X1, X2);
        pminub(a, X0, X1);
        sse_rr(a, 0x66, 0xEF, X0, X2); return;
    case 0x3E:                                                 /* MAXSB8 */
        if (g_has_sse41) { pmaxsb(a, X0, X1); return; }
        mov_r_imm64(a, TC, 0x8080808080808080ULL); movq_x_r(a, X2, TC);
        sse_rr(a, 0x66, 0xEF, X0, X2); sse_rr(a, 0x66, 0xEF, X1, X2);
        pmaxub(a, X0, X1);
        sse_rr(a, 0x66, 0xEF, X0, X2); return;
    case 0x3B:                                                 /* MINUW4 */
        if (g_has_sse41) { pminuw(a, X0, X1); return; }
        movaps_x_x(a, X2, X0); psubusw(a, X2, X1); psubw_x(a, X0, X2); return;
    default:                                                   /* MAXUW4 */
        if (g_has_sse41) { pmaxuw(a, X0, X1); return; }
        movaps_x_x(a, X2, X0); psubusw(a, X2, X1);
        movaps_x_x(a, X0, X1); paddw_x(a, X0, X2); return;
    }
}

/* Returns 0 when the instruction was emitted, -1 to fall back. */
static int emit_mvi(Asm *a, int func, int ra, int rb, int rc, int islit, int lit)
{
    switch (func) {
    case 0x31:                                                 /* PERR   */
        ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
        movq_x_r(a, X0, TA); movq_x_r(a, X1, TB);
        psadbw(a, X0, X1);                 /* sum of absolute byte diffs   */
        movq_r_x(a, TA, X0); st_ireg(a, rc, TA); return 0;
    case 0x34:                                                 /* UNPKBW */
        ld_opb(a, TB, rb, islit, lit);
        movq_x_r(a, X0, TB); pxor_x_x(a, X1, X1);
        punpcklbw(a, X0, X1);
        movq_r_x(a, TA, X0); st_ireg(a, rc, TA); return 0;
    case 0x35:                                                 /* UNPKBL */
        ld_opb(a, TB, rb, islit, lit);
        mov_r_r(a, TA, TB); alu_ri(a, D_AND, TA, 0xFF);
        mov_r_r(a, TC, TB); alu_ri(a, D_AND, TC, 0xFF00);
        shift_imm(a, S_SHL, TC, 24);
        alu_rr(a, X_OR, TA, TC); st_ireg(a, rc, TA); return 0;
    case 0x36:                                                 /* PKWB   */
        ld_opb(a, TB, rb, islit, lit);
        mov_r_imm64(a, TA, 0x00FF00FF00FF00FFULL); movq_x_r(a, X1, TA);
        movq_x_r(a, X0, TB); pand_x(a, X0, X1);
        packuswb(a, X0, X0);               /* nothing saturates: all <= 255 */
        movd_r_x(a, TA, X0); st_ireg(a, rc, TA); return 0;
    case 0x37:                                                 /* PKLB   */
        ld_opb(a, TB, rb, islit, lit);
        mov_r_r(a, TA, TB); alu_ri(a, D_AND, TA, 0xFF);
        mov_r_r(a, TC, TB); shift_imm(a, S_SHR, TC, 32);
        alu_ri(a, D_AND, TC, 0xFF); shift_imm(a, S_SHL, TC, 8);
        alu_rr(a, X_OR, TA, TC); st_ireg(a, rc, TA); return 0;
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x3C: case 0x3D: case 0x3E: case 0x3F:
        ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
        movq_x_r(a, X0, TA); movq_x_r(a, X1, TB);
        emit_mvi_minmax(a, func);
        movq_r_x(a, TA, X0); st_ireg(a, rc, TA); return 0;
    case 0x78:                                                 /* FTOIS  */
        ld_freg(a, TA, ra);
        emit_t_to_s(a, TC, TA);
        movsxd_r(a, TC, TC); st_ireg(a, rc, TC); return 0;
    default: return -1;
    }
}

/* ---- floating point (opcodes 0x14..0x17) ------------------------------ */
static int emit_fp(Asm *a, uint32_t insn)
{
    int op   = (int)(insn >> 26);
    int fa   = (int)((insn >> 21) & 31);
    int fb   = (int)((insn >> 16) & 31);
    int fc   = (int)(insn & 31);
    int func = (int)((insn >> 5) & 0x7FF);

    if (op == 0x17) {                           /* FLTL: bit manipulation  */
        switch (func) {
        case 0x020:                                            /* CPYS    */
        case 0x021:                                            /* CPYSN   */
            ld_freg(a, TA, fa);
            if (func == 0x021) not_r(a, TA);
            shift_imm(a, S_SHR, TA, 63); shift_imm(a, S_SHL, TA, 63);
            ld_freg(a, TB, fb);
            shift_imm(a, S_SHL, TB, 1); shift_imm(a, S_SHR, TB, 1);
            alu_rr(a, X_OR, TA, TB); st_freg(a, fc, TA); return 0;
        case 0x022:                                            /* CPYSE   */
            ld_freg(a, TA, fa);
            shift_imm(a, S_SHR, TA, 52); shift_imm(a, S_SHL, TA, 52);
            ld_freg(a, TB, fb);
            shift_imm(a, S_SHL, TB, 12); shift_imm(a, S_SHR, TB, 12);
            alu_rr(a, X_OR, TA, TB); st_freg(a, fc, TA); return 0;
        case 0x024:                                            /* MT_FPCR */
            ld_freg(a, TA, fa); st_cpu(a, OFF_FPCR, TA); return 0;
        case 0x025:                                            /* MF_FPCR */
            ld_cpu(a, TA, OFF_FPCR); st_freg(a, fa, TA); return 0;
        case 0x010: {                                          /* CVTLQ   */
            ld_freg(a, TB, fb);
            mov_r_r(a, TA, TB);
            shift_imm(a, S_SHR, TA, 62); shift_imm(a, S_SHL, TA, 30);
            shift_imm(a, S_SHR, TB, 29); alu_ri(a, D_AND, TB, 0x3FFFFFFF);
            alu_rr(a, X_OR, TA, TB);
            movsxd_r(a, TA, TA); st_freg(a, fc, TA); return 0;
        }
        case 0x030: case 0x130: case 0x530: {                  /* CVTQL   */
            ld_freg(a, TB, fb);
            mov_r_r(a, TA, TB);
            shift_imm(a, S_SHR, TA, 30); alu_ri(a, D_AND, TA, 3);
            shift_imm(a, S_SHL, TA, 62);
            alu_ri(a, D_AND, TB, 0x3FFFFFFF); shift_imm(a, S_SHL, TB, 29);
            alu_rr(a, X_OR, TA, TB); st_freg(a, fc, TA); return 0;
        }
        case 0x02A: case 0x02B: case 0x02C:
        case 0x02D: case 0x02E: case 0x02F: {                  /* FCMOVxx */
            /* The test is on the bit pattern of Fa: zero ignores the sign
             * and a NaN never traps, so pure integer logic is exact.      */
            int cc, wide = (func != 0x02A && func != 0x02B);
            ld_freg(a, TA, fa);
            mov_r_r(a, TD, TA); shift_imm(a, S_SHL, TD, 1);   /* magnitude */
            ld_freg(a, TB, fb);
            ld_freg(a, TC, fc);
            if (!wide) {
                test_rr(a, TD, TD);
                cc = (func == 0x02A) ? CC_E : CC_NE;          /* EQ / NE   */
            } else {
                /* LT = neg & !zero   GE = !neg | zero
                 * LE = neg |  zero   GT = !neg & !zero                    */
                int zcc = (func == 0x02C || func == 0x02F) ? CC_NE : CC_E;
                int scc = (func == 0x02C || func == 0x02E) ? CC_S  : CC_NS;
                int conj= (func == 0x02C || func == 0x02F);
                test_rr(a, TD, TD); setcc_r(a, zcc, R8);
                test_rr(a, TA, TA); setcc_r(a, scc, R9);
                alu32_rr(a, conj ? X_AND : X_OR, R8, R9);
                test_ri(a, R8, 1); cc = CC_NE;
            }
            cmov_rr(a, cc, TC, TB);
            st_freg(a, fc, TC); return 0;
        }
        default: return -1;
        }
    }

    if (op == 0x14) {                           /* ITFP                    */
        int rnd = (func >> 6) & 3;
        switch (func & 0x3F) {
        case 0x04:                                             /* ITOFS   */
            ld_ireg(a, TA, fa); zext32(a, TA);
            emit_s_to_t(a, TB, TA); st_freg(a, fc, TB); return 0;
        case 0x24:                                             /* ITOFT   */
            ld_ireg(a, TA, fa); st_freg(a, fc, TA); return 0;
        case 0x0B:                                             /* SQRTS   */
            emit_set_round(a, rnd);
            ld_freg(a, TA, fb); emit_t_to_s(a, TC, TA);
            movd_x_r(a, X1, TC); sqrtss(a, X0, X1);
            emit_nanfix(a, 0, X0, X1, X1);
            movd_r_x(a, TC, X0);
            emit_s_to_t(a, TA, TC); st_freg(a, fc, TA); return 0;
        case 0x2B:                                             /* SQRTT   */
            emit_set_round(a, rnd);
            ld_fx(a, X1, fb); sqrtsd(a, X0, X1);
            emit_nanfix(a, 1, X0, X1, X1);
            st_fx(a, fc, X0); return 0;
        default: return -1;
        }
    }

    /* opcodes 0x15 / 0x16 : IEEE arithmetic.  base6 and the rounding field
     * are valid for every qualified form; the trap-mode bits pick CVTST
     * over CVTTS. */
    {
    int base = func & 0x3F;
    int rnd  = (func >> 6) & 3;
    int trp  = (func >> 8) & 7;
    int isS  = (base & 0x20) == 0;
    int sub  = base & 0x1F;

    /* An S-format operation does not read the register as a double: it takes
     * the single from <63:62>||<58:29>, computes in float32 and re-expands.
     * CVTQS produces a single even though bit 0x20 is set. */
    if (isS || base == 0x3C) {
        if (base == 0x3C) {                                    /* CVTQS   */
            emit_set_round(a, rnd);
            ld_freg(a, TA, fb);
            cvtsi2ss(a, X0, TA);
            movd_r_x(a, TC, X0);
            emit_s_to_t(a, TA, TC); st_freg(a, fc, TA); return 0;
        }
        if (sub > 0x03) return -1;
        emit_set_round(a, rnd);
        ld_freg(a, TA, fa); emit_t_to_s(a, TC, TA);
        ld_freg(a, TB, fb); emit_t_to_s(a, TD, TB);
        movd_x_r(a, X0, TC); movd_x_r(a, X1, TD);
        movaps_x_x(a, X4, X0);
        switch (sub) {
        case 0x00: addss(a, X0, X1); break;
        case 0x01: subss(a, X0, X1); break;
        case 0x02: mulss(a, X0, X1); break;
        default:   divss(a, X0, X1); break;
        }
        emit_nanfix(a, 0, X0, X4, X1);
        movd_r_x(a, TC, X0);
        emit_s_to_t(a, TA, TC); st_freg(a, fc, TA); return 0;
    }


    switch (sub) {
    case 0x00: case 0x01: case 0x02: case 0x03:   /* ADDT SUBT MULT DIVT  */
        emit_set_round(a, rnd);
        ld_fx(a, X0, fa); ld_fx(a, X1, fb);
        movaps_x_x(a, X4, X0);
        switch (sub) {
        case 0x00: addsd(a, X0, X1); break;
        case 0x01: subsd(a, X0, X1); break;
        case 0x02: mulsd(a, X0, X1); break;
        default:   divsd(a, X0, X1); break;
        }
        emit_nanfix(a, 1, X0, X4, X1);
        st_fx(a, fc, X0); return 0;
    case 0x0B:                                                 /* SQRTT   */
        emit_set_round(a, rnd);
        ld_fx(a, X1, fb); sqrtsd(a, X0, X1);
        emit_nanfix(a, 1, X0, X1, X1);
        st_fx(a, fc, X0); return 0;
    case 0x04: case 0x05: case 0x06: case 0x07: {  /* CMPTUN EQ LT LE     */
        int pred = sub == 0x04 ? CMP_UNORD : sub == 0x05 ? CMP_EQ
                 : sub == 0x06 ? CMP_LT    : CMP_LE;
        ld_fx(a, X0, fa); ld_fx(a, X1, fb);
        cmpsd_i(a, X0, X1, (uint8_t)pred);
        movq_r_x(a, TA, X0);
        mov_r_imm64(a, TB, 0x4000000000000000ULL);
        alu_rr(a, X_AND, TA, TB);
        st_freg(a, fc, TA); return 0;
    }
    case 0x0C:
        if ((trp & 3) == 2) {                                  /* CVTST   */
            ld_freg(a, TA, fb); emit_t_to_s(a, TC, TA);
            movd_x_r(a, X0, TC); cvtss2sd(a, X0, X0);
            st_fx(a, fc, X0); return 0;
        }
        emit_set_round(a, rnd);                                /* CVTTS   */
        ld_fx(a, X0, fb); cvtsd2ss(a, X0, X0);
        movd_r_x(a, TC, X0);
        emit_s_to_t(a, TA, TC); st_freg(a, fc, TA); return 0;
    case 0x0F:                                                 /* CVTTQ   */
        emit_cvttq(a, fb, fc, rnd); return 0;
    case 0x1E:                                                 /* CVTQT   */
        emit_set_round(a, rnd);
        ld_freg(a, TA, fb); cvtsi2sd(a, X0, TA);
        st_fx(a, fc, X0); return 0;
    default: return -1;
    }
    }
}

/* byte masks for the EXT/INS/MSK family */
static uint64_t size_mask(int nbytes)
{ return nbytes >= 8 ? ~0ULL : ((1ULL << (8 * nbytes)) - 1); }

/* sh = 8*(Rb&7) into CL */
static void emit_shcount(Asm *a, int rb, int islit, int lit)
{
    if (islit) { mov_r32_imm(a, TB, (unsigned)(8 * (lit & 7))); return; }
    ld_ireg(a, TB, rb);
    alu_ri(a, D_AND, TB, 7);
    shift_imm(a, S_SHL, TB, 3);
}
/* CL = (64 - 8*(Rb&7)) & 63 : the architectural count for the *H variants.
 * The Alpha shifter truncates the count to 6 bits, so Rb&7 == 0 means a
 * shift of 0 (identity) rather than 64. */
static void emit_shcount_h(Asm *a, int rb, int islit, int lit)
{
    if (islit) { mov_r32_imm(a, TB, (unsigned)((64 - 8 * (lit & 7)) & 63)); return; }
    emit_shcount(a, rb, islit, lit);          /* CL = sh */
    neg_r(a, TB);                             /* x86 masks the count to 6 bits */
}

/* CL = 63 - 8*(Rb&7).  INSxH and MSKxH are defined as the *high* half of a
 * 128-bit shift, so a byte offset of 0 must yield 0 rather than the identity.
 * Shifting by 1 and then by 63-sh reproduces that exactly. */
static void emit_shcount63(Asm *a, int rb, int islit, int lit)
{
    if (islit) { mov_r32_imm(a, TB, (unsigned)(63 - 8 * (lit & 7))); return; }
    emit_shcount(a, rb, islit, lit);          /* CL = sh */
    mov_r32_imm(a, TE, 63);
    alu_rr(a, X_SUB, TE, TB);                 /* TE = 63 - sh */
    mov_r_r(a, TB, TE);
}

/* ---------------------------------------------------------------------- */
/* Translate one instruction.  Returns 1 if the block must end.           */
/* ---------------------------------------------------------------------- */
static int translate_insn(Asm *a, uint32_t insn, uint64_t pc, uint64_t *fall)
{
    int op   = (int)(insn >> 26);
    int ra   = (int)((insn >> 21) & 31);
    int rb   = (int)((insn >> 16) & 31);
    int rc   = (int)(insn & 31);
    int func = (int)((insn >> 5) & 0x7F);
    int islit= (int)((insn >> 12) & 1);
    int lit  = (int)((insn >> 13) & 0xFF);
    int32_t disp16 = (int32_t)(int16_t)(insn & 0xFFFF);
    uint64_t next = pc + 4;
    *fall = next;

    switch (op) {

    /* ---- LDA / LDAH --------------------------------------------------- */
    case 0x08: /* LDA  Ra <- Rb + disp   */
    case 0x09: /* LDAH Ra <- Rb + disp<<16 */
    {
        int32_t d = (op == 0x09) ? (disp16 << 16) : disp16;
        if (ra == 31) return 0;               /* pure no-op */
        ld_ireg(a, TA, rb);
        if (d) alu_ri(a, D_ADD, TA, d);
        st_ireg(a, ra, TA);
        return 0;
    }

    /* ---- integer loads ------------------------------------------------ */
    case 0x0A: /* LDBU */ case 0x0C: /* LDWU */
    case 0x28: /* LDL  */ case 0x29: /* LDQ  */
    case 0x0B: /* LDQ_U */
    {
        if (ra == 31) return 0;               /* prefetch hint: ignore */
        ld_ireg(a, TB, rb);
        if (op == 0x0B) {                     /* address &= ~7 */
            if (disp16) alu_ri(a, D_ADD, TB, disp16);
            alu_ri(a, D_AND, TB, -8);
            ldq_via(a, TA, TB, 0);
        } else {
            switch (op) {
            case 0x0A: ldbu_via(a, TA, TB, disp16); break;
            case 0x0C: ldwu_via(a, TA, TB, disp16); break;
            case 0x28: ldl_via (a, TA, TB, disp16); break;  /* movslq */
            case 0x29: ldq_via (a, TA, TB, disp16); break;
            }
        }
        st_ireg(a, ra, TA);
        return 0;
    }

    /* ---- integer stores ----------------------------------------------- */
    case 0x0E: /* STB */ case 0x0D: /* STW */
    case 0x2C: /* STL */ case 0x2D: /* STQ */
    case 0x0F: /* STQ_U */
    {
        ld_ireg(a, TB, rb);
        ld_ireg(a, TA, ra);
        if (op == 0x0F) {
            if (disp16) alu_ri(a, D_ADD, TB, disp16);
            alu_ri(a, D_AND, TB, -8);
            stq_via(a, TB, 0, TA);
        } else {
            switch (op) {
            case 0x0E: stb_via(a, TB, disp16, TA); break;
            case 0x0D: stw_via(a, TB, disp16, TA); break;
            case 0x2C: stl_via(a, TB, disp16, TA); break;
            case 0x2D: stq_via(a, TB, disp16, TA); break;
            }
        }
        return 0;
    }

    /* ---- FP loads / stores -------------------------------------------- */
    case 0x23: /* LDT : raw 64-bit */
        if (ra == 31) return 0;
        ld_ireg(a, TB, rb); ldq_via(a, TA, TB, disp16); st_freg(a, ra, TA);
        return 0;
    case 0x27: /* STT */
        ld_ireg(a, TB, rb); ld_freg(a, TA, ra); stq_via(a, TB, disp16, TA);
        return 0;
    case 0x22: /* LDS : S-format memory -> T-format register (bit exact) */
        if (ra == 31) return 0;
        ld_ireg(a, TB, rb);
        ldlu_via(a, TA, TB, disp16);        /* zero-extended 32-bit load   */
        emit_s_to_t(a, TC, TA);
        st_freg(a, ra, TC);
        return 0;
    case 0x26: /* STS */
        ld_ireg(a, TB, rb); ld_freg(a, TA, ra);
        emit_t_to_s(a, TC, TA);
        stl_via(a, TB, disp16, TC);
        return 0;
    case 0x20: case 0x21: case 0x24: case 0x25: /* VAX F/G formats */
        emit_helper(a, (void *)helper_fp_mem, insn);
        return 0;

    /* ---- operate: arithmetic (0x10) ----------------------------------- */
    case 0x10:
        switch (func) {
        case 0x00: case 0x20: /* ADDL / ADDQ */
        case 0x40: case 0x60: /* ADDL/V, ADDQ/V (trap not modelled) */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_ADD, TA, TB);
            if (func == 0x00 || func == 0x40) movsxd_r(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x09: case 0x29: /* SUBL / SUBQ */
        case 0x49: case 0x69:
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_SUB, TA, TB);
            if (func == 0x09 || func == 0x49) movsxd_r(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x02: case 0x22: case 0x12: case 0x32:   /* S4ADDL/Q S8ADDL/Q */
        case 0x0B: case 0x2B: case 0x1B: case 0x3B: { /* S4SUBL/Q S8SUBL/Q */
            int scale8 = (func == 0x12 || func == 0x32 || func == 0x1B || func == 0x3B);
            int is_sub = (func == 0x0B || func == 0x2B || func == 0x1B || func == 0x3B);
            int is_long= (func == 0x02 || func == 0x12 || func == 0x0B || func == 0x1B);
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            shift_imm(a, S_SHL, TA, scale8 ? 3 : 2);
            alu_rr(a, is_sub ? X_SUB : X_ADD, TA, TB);
            if (is_long) movsxd_r(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        }
        case 0x1D: case 0x2D: case 0x3D: case 0x4D: case 0x6D: { /* CMPxx */
            int cc = func == 0x1D ? CC_B  :   /* CMPULT */
                     func == 0x2D ? CC_E  :   /* CMPEQ  */
                     func == 0x3D ? CC_BE :   /* CMPULE */
                     func == 0x4D ? CC_L  :   /* CMPLT  */
                                    CC_LE;    /* CMPLE  */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_CMP, TA, TB);
            setcc_r(a, cc, TD);
            movzx_b(a, TA, TD);
            st_ireg(a, rc, TA); return 0;
        }
        case 0x0F: /* CMPBGE : bit i = (Ra_i >= Rb_i), unsigned bytes */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            movq_x_r(a, X0, TA); movq_x_r(a, X1, TB);
            movaps_x_x(a, X2, X0);
            pmaxub(a, X0, X1);
            pcmpeqb(a, X0, X2);            /* 0xFF in every byte where a>=b */
            pmovmskb(a, TA, X0);
            alu_ri(a, D_AND, TA, 0xFF);    /* the zeroed high lanes compare
                                            * equal, so keep 8 bits         */
            st_ireg(a, rc, TA); return 0;
        default:
            emit_helper(a, (void *)helper_int_op, insn); return 0;
        }

    /* ---- operate: logical / conditional move (0x11) -------------------- */
    case 0x11:
        switch (func) {
        case 0x00: /* AND */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_AND, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x08: /* BIC : Ra & ~Rb */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            not_r(a, TB); alu_rr(a, X_AND, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x20: /* BIS */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_OR, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x28: /* ORNOT : Ra | ~Rb */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            not_r(a, TB); alu_rr(a, X_OR, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x40: /* XOR */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            alu_rr(a, X_XOR, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x48: /* EQV : Ra ^ ~Rb */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            not_r(a, TB); alu_rr(a, X_XOR, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x14: case 0x16: case 0x24: case 0x26:
        case 0x44: case 0x46: case 0x64: case 0x66: { /* CMOVxx */
            /* Rc is only written when the condition holds. */
            ld_ireg(a, TA, ra);
            ld_opb (a, TB, rb, islit, lit);
            ld_ireg(a, TC, rc);                 /* previous value */
            int cc;
            switch (func) {
            case 0x14: test_ri(a, TA, 1); cc = CC_NE; break; /* CMOVLBS */
            case 0x16: test_ri(a, TA, 1); cc = CC_E;  break; /* CMOVLBC */
            case 0x24: test_rr(a, TA, TA); cc = CC_E;  break; /* CMOVEQ */
            case 0x26: test_rr(a, TA, TA); cc = CC_NE; break; /* CMOVNE */
            case 0x44: test_rr(a, TA, TA); cc = CC_S;  break; /* CMOVLT */
            case 0x46: test_rr(a, TA, TA); cc = CC_NS; break; /* CMOVGE */
            case 0x64: test_rr(a, TA, TA); cc = CC_LE; break; /* CMOVLE */
            default:   test_rr(a, TA, TA); cc = CC_G;  break; /* CMOVGT */
            }
            cmov_rr(a, cc, TC, TB);
            st_ireg(a, rc, TC); return 0;
        }
        case 0x61: /* AMASK : Rc = Rb & ~implemented_features (EV67) */
            ld_opb(a, TA, rb, islit, lit);
            mov_r_imm64(a, TB, ~(uint64_t)ALPHA_AMASK_IMPL);
            alu_rr(a, X_AND, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x6C: /* IMPLVER */
            mov_r_imm64(a, TA, 2); st_ireg(a, rc, TA); return 0;
        default:
            emit_helper(a, (void *)helper_int_op, insn); return 0;
        }

    /* ---- operate: shift / byte manipulation (0x12) --------------------- */
    case 0x12:
        switch (func) {
        case 0x39: case 0x34: case 0x3C: { /* SLL / SRL / SRA */
            int d = func == 0x39 ? S_SHL : func == 0x34 ? S_SHR : S_SAR;
            ld_ireg(a, TA, ra);
            if (islit) shift_imm(a, d, TA, (uint8_t)(lit & 63));
            else { ld_ireg(a, TB, rb); shift_cl(a, d, TA); }
            st_ireg(a, rc, TA); return 0;
        }
        case 0x30: case 0x31: { /* ZAP / ZAPNOT */
            if (!islit) {
                /* the byte-enable mask comes from Rb at run time: one load
                 * from a 256-entry table expands it */
                ld_ireg(a, TA, ra); ld_ireg(a, TB, rb);
                alu_ri(a, D_AND, TB, 0xFF);
                if (func == 0x30) alu_ri(a, D_XOR, TB, 0xFF);
                mov_r_imm64(a, TC, (uint64_t)(uintptr_t)g_zap_mask);
                lea_isd(a, TC, TC, TB, 8, 0);
                mov_r_m(a, TC, TC, 0);
                alu_rr(a, X_AND, TA, TC);
                st_ireg(a, rc, TA); return 0;
            }
            unsigned m = (unsigned)lit & 0xFF;
            if (func == 0x30) m = ~m & 0xFF;          /* ZAP: clear where set */
            uint64_t mask = 0;
            for (int i = 0; i < 8; i++) if (m & (1u << i)) mask |= 0xFFULL << (8 * i);
            ld_ireg(a, TA, ra);
            mov_r_imm64(a, TB, mask);
            alu_rr(a, X_AND, TA, TB);
            st_ireg(a, rc, TA); return 0;
        }
        /* EXTxL : (Ra >> sh) & mask */
        case 0x06: case 0x16: case 0x26: case 0x36: {
            int n = func == 0x06 ? 1 : func == 0x16 ? 2 : func == 0x26 ? 4 : 8;
            ld_ireg(a, TA, ra);
            emit_shcount(a, rb, islit, lit);
            shift_cl(a, S_SHR, TA);
            if (n < 8) { mov_r_imm64(a, TC, size_mask(n)); alu_rr(a, X_AND, TA, TC); }
            st_ireg(a, rc, TA); return 0;
        }
        /* EXTxH : (Ra << ((64-sh)&63)) & mask */
        case 0x5A: case 0x6A: case 0x7A: {
            int n = func == 0x5A ? 2 : func == 0x6A ? 4 : 8;
            ld_ireg(a, TA, ra);
            emit_shcount_h(a, rb, islit, lit);
            shift_cl(a, S_SHL, TA);
            if (n < 8) { mov_r_imm64(a, TC, size_mask(n)); alu_rr(a, X_AND, TA, TC); }
            st_ireg(a, rc, TA); return 0;
        }
        /* INSxL : (Ra & mask) << sh */
        case 0x0B: case 0x1B: case 0x2B: case 0x3B: {
            int n = func == 0x0B ? 1 : func == 0x1B ? 2 : func == 0x2B ? 4 : 8;
            ld_ireg(a, TA, ra);
            if (n < 8) { mov_r_imm64(a, TC, size_mask(n)); alu_rr(a, X_AND, TA, TC); }
            emit_shcount(a, rb, islit, lit);
            shift_cl(a, S_SHL, TA);
            st_ireg(a, rc, TA); return 0;
        }
        /* INSxH : high half of ((Ra & mask) << sh) — 0 when sh == 0 */
        case 0x57: case 0x67: case 0x77: {
            int n = func == 0x57 ? 2 : func == 0x67 ? 4 : 8;
            ld_ireg(a, TA, ra);
            if (n < 8) { mov_r_imm64(a, TC, size_mask(n)); alu_rr(a, X_AND, TA, TC); }
            emit_shcount63(a, rb, islit, lit);
            shift_imm(a, S_SHR, TA, 1);
            shift_cl (a, S_SHR, TA);
            st_ireg(a, rc, TA); return 0;
        }
        /* MSKxL : Ra & ~(mask << sh) */
        case 0x02: case 0x12: case 0x22: case 0x32: {
            int n = func == 0x02 ? 1 : func == 0x12 ? 2 : func == 0x22 ? 4 : 8;
            mov_r_imm64(a, TC, size_mask(n));
            emit_shcount(a, rb, islit, lit);
            shift_cl(a, S_SHL, TC);
            not_r(a, TC);
            ld_ireg(a, TA, ra);
            alu_rr(a, X_AND, TA, TC);
            st_ireg(a, rc, TA); return 0;
        }
        /* MSKxH : the mask is the high half of (mask << sh) — 0 when sh == 0 */
        case 0x52: case 0x62: case 0x72: {
            int n = func == 0x52 ? 2 : func == 0x62 ? 4 : 8;
            mov_r_imm64(a, TC, size_mask(n));
            emit_shcount63(a, rb, islit, lit);
            shift_imm(a, S_SHR, TC, 1);
            shift_cl (a, S_SHR, TC);
            not_r(a, TC);
            ld_ireg(a, TA, ra);
            alu_rr(a, X_AND, TA, TC);
            st_ireg(a, rc, TA); return 0;
        }
        default:
            emit_helper(a, (void *)helper_int_op, insn); return 0;
        }

    /* ---- operate: multiply (0x13) -------------------------------------- */
    case 0x13:
        switch (func) {
        case 0x00: case 0x40: /* MULL */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            imul_rr(a, TA, TB); movsxd_r(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x20: case 0x60: /* MULQ */
            ld_ireg(a, TA, ra); ld_opb(a, TB, rb, islit, lit);
            imul_rr(a, TA, TB); st_ireg(a, rc, TA); return 0;
        case 0x30: /* UMULH : high 64 bits of the unsigned product */
            ld_ireg(a, RAX, ra); ld_opb(a, TB, rb, islit, lit);
            mul_r(a, TB);                    /* RDX:RAX = RAX * TB */
            st_ireg(a, rc, RDX); return 0;
        default:
            emit_helper(a, (void *)helper_int_op, insn); return 0;
        }

    /* ---- operate: byte/word extension + count (0x1C) -------------------- */
    case 0x1C:
        switch (func) {
        case 0x00: /* SEXTB (operand is Rb) */
            ld_opb(a, TA, rb, islit, lit); movsx_b(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x01: /* SEXTW */
            ld_opb(a, TA, rb, islit, lit); movsx_w(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x30: /* CTPOP */
            ld_opb(a, TA, rb, islit, lit); popcnt_rr(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x32: /* CTLZ */
            ld_opb(a, TA, rb, islit, lit); lzcnt_rr(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x33: /* CTTZ */
            ld_opb(a, TA, rb, islit, lit); tzcnt_rr(a, TA, TA);
            st_ireg(a, rc, TA); return 0;
        case 0x70: /* FTOIT : raw bits of Fa -> Rc */
            ld_freg(a, TA, ra); st_ireg(a, rc, TA); return 0;
        default:
            /* the multimedia extension: real SSE, see emit_mvi() */
            if (emit_mvi(a, func, ra, rb, rc, islit, lit) == 0) return 0;
            emit_helper(a, (void *)helper_int_op, insn); return 0;
        }

    /* ---- floating point: real SSE2, see emit_fp() ----------------------- */
    case 0x14: case 0x15: case 0x16: case 0x17:
        if (emit_fp(a, insn) == 0) return 0;
        emit_helper(a, (void *)helper_fp_op, insn);
        return 0;

    /* ---- misc (0x18): memory barriers, prefetch hints, counters --------- */
    case 0x18: {
        unsigned mfunc = insn & 0xFFFF;
        if (mfunc == 0xC000 || mfunc == 0xE000 || mfunc == 0xF000) {
            emit_helper(a, (void *)helper_int_op, insn);   /* RPCC / RC / RS */
        }
        return 0;                                          /* TRAPB/EXCB/MB/... */
    }

    /* ---- JMP / JSR / RET / JSR_COROUTINE (0x1A) ------------------------- */
    case 0x1A:
        ld_ireg(a, TB, rb);                 /* read target BEFORE writing Ra */
        alu_ri(a, D_AND, TB, -4);
        if (ra != 31) { mov_r_imm64(a, TA, next); st_ireg(a, ra, TA); }
        st_cpu(a, OFF_PC, TB);
        emit_frame_leave(a);
        ret_(a);
        return 1;

    /* ---- unconditional branches ---------------------------------------- */
    case 0x30: case 0x34: { /* BR / BSR */
        int32_t bd = (int32_t)(insn & 0x1FFFFF);
        if (bd & 0x100000) bd -= 0x200000;
        uint64_t target = next + 4ULL * (int64_t)bd;
        if (ra != 31) { mov_r_imm64(a, TA, next); st_ireg(a, ra, TA); }
        emit_exit(a, target, EXIT_BLOCK_END);
        return 1;
    }

    /* ---- conditional branches ------------------------------------------ */
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x3C: case 0x3D: case 0x3E: case 0x3F:
    case 0x31: case 0x32: case 0x33: case 0x35: case 0x36: case 0x37: {
        int32_t bd = (int32_t)(insn & 0x1FFFFF);
        if (bd & 0x100000) bd -= 0x200000;
        uint64_t target = next + 4ULL * (int64_t)bd;
        int cc;
        if (op >= 0x38) {                    /* integer condition on Ra */
            ld_ireg(a, TA, ra);
            switch (op) {
            case 0x38: test_ri(a, TA, 1); cc = CC_E;  break; /* BLBC */
            case 0x3C: test_ri(a, TA, 1); cc = CC_NE; break; /* BLBS */
            case 0x39: test_rr(a, TA, TA); cc = CC_E;  break; /* BEQ */
            case 0x3D: test_rr(a, TA, TA); cc = CC_NE; break; /* BNE */
            case 0x3A: test_rr(a, TA, TA); cc = CC_S;  break; /* BLT */
            case 0x3E: test_rr(a, TA, TA); cc = CC_NS; break; /* BGE */
            case 0x3B: test_rr(a, TA, TA); cc = CC_LE; break; /* BLE */
            default:   test_rr(a, TA, TA); cc = CC_G;  break; /* BGT */
            }
        } else {
            /* FP branches test the *bit pattern*: zero ignores the sign and
             * NaNs never trap, so pure integer logic is exact.             */
            ld_freg(a, TA, ra);
            mov_r_r(a, TD, TA);
            shift_imm(a, S_SHL, TD, 1);      /* TD = value with sign removed */
            switch (op) {
            case 0x31: test_rr(a, TD, TD); cc = CC_E;  break; /* FBEQ */
            case 0x35: test_rr(a, TD, TD); cc = CC_NE; break; /* FBNE */
            case 0x32: /* FBLT : sign set AND non-zero */
                test_rr(a, TD, TD); setcc_r(a, CC_NE, TC);
                test_rr(a, TA, TA); setcc_r(a, CC_S,  TE);
                alu32_rr(a, X_AND, TC, TE);
                test_ri(a, TC, 1); cc = CC_NE; break;
            case 0x36: /* FBGE : sign clear OR zero */
                test_rr(a, TD, TD); setcc_r(a, CC_E,  TC);
                test_rr(a, TA, TA); setcc_r(a, CC_NS, TE);
                alu32_rr(a, X_OR, TC, TE);
                test_ri(a, TC, 1); cc = CC_NE; break;
            case 0x33: /* FBLE : sign set OR zero */
                test_rr(a, TD, TD); setcc_r(a, CC_E, TC);
                test_rr(a, TA, TA); setcc_r(a, CC_S, TE);
                alu32_rr(a, X_OR, TC, TE);
                test_ri(a, TC, 1); cc = CC_NE; break;
            default:   /* FBGT : sign clear AND non-zero */
                test_rr(a, TD, TD); setcc_r(a, CC_NE, TC);
                test_rr(a, TA, TA); setcc_r(a, CC_NS, TE);
                alu32_rr(a, X_AND, TC, TE);
                test_ri(a, TC, 1); cc = CC_NE; break;
            }
        }
        uint32_t *taken = jcc_rel32(a, cc);
        emit_exit(a, next, EXIT_BLOCK_END);          /* not taken */
        patch_rel32(taken, a->p);
        emit_exit(a, target, EXIT_BLOCK_END);        /* taken */
        return 1;
    }

    /* ---- PALcode space: our guest->host call gate ---------------------
     * User-mode Alpha code never issues call_pal, so opcode 0 is free to
     * act as the PE/Unix boundary: the helper runs a native routine and we
     * return to ra, exactly like a real imported function would.        */
    case 0x00:
        emit_helper(a, (void *)helper_native, insn);
        ld_cpu(a, TB, OFF_RETPC);           /* the callout chooses where to resume:
                                             * ra normally, but the Alpha divide
                                             * helpers return through t9 ($23) */
        st_cpu(a, OFF_PC, TB);
        emit_frame_leave(a);
        ret_(a);
        return 1;

    default:
        emit_exit(a, pc, EXIT_UNIMPL);
        return 1;
    }
}

/* ---------------------------------------------------------------------- */
int jit_init(JitCtx *j, size_t cache_bytes, size_t max_blocks)
{
    unsigned ax, bx, cx, dx;
    g_has_sse41 = __get_cpuid(1, &ax, &bx, &cx, &dx) && (cx & (1u << 19))
                  && !getenv("AXP64_NO_SSE41");
    for (int m = 0; m < 256; m++) {
        uint64_t k = 0;
        for (int i = 0; i < 8; i++) if (m & (1u << i)) k |= 0xFFULL << (8 * i);
        g_zap_mask[m] = k;
    }
    memset(j, 0, sizeof(*j));
    j->cache = rwx_alloc(cache_bytes);
    if (!j->cache) return -1;
    j->cache_size = cache_bytes;
    j->cache_ptr  = j->cache;
    {   /* the two NaN-selection stubs live at the head of the code cache */
        Asm st = { j->cache_ptr, j->cache + cache_bytes };
        g_nan_stub[0] = st.p; emit_nan_stub(&st, 0);
        g_nan_stub[1] = st.p; emit_nan_stub(&st, 1);
        j->cache_ptr = st.p;
    }
    j->hash_size  = 1u << 16;
    j->hash       = calloc(j->hash_size, sizeof(TBlock *));
    j->blocks     = calloc(max_blocks, sizeof(TBlock));
    j->max_blocks = max_blocks;
    return (j->hash && j->blocks) ? 0 : -1;
}

static size_t hash_pc(JitCtx *j, uint64_t pc)
{ return ((pc >> 2) ^ (pc >> 17)) & (j->hash_size - 1); }

TBlock *jit_lookup(JitCtx *j, uint64_t pc)
{
    for (TBlock *b = j->hash[hash_pc(j, pc)]; b; b = b->hash_next)
        if (b->guest_pc == pc) return b;
    return NULL;
}

TBlock *jit_translate(JitCtx *j, CPUAlpha *cpu, uint64_t pc)
{
    (void)cpu;
    if (j->nblocks >= j->max_blocks) return NULL;
    if ((size_t)(j->cache_ptr - j->cache) + 65536 > j->cache_size) return NULL;

    TBlock *b = &j->blocks[j->nblocks++];
    b->guest_pc = pc;
    b->code     = j->cache_ptr;

    Asm as = { j->cache_ptr, j->cache + j->cache_size };
    Asm *a = &as;
    emit_frame_enter(a);           /* RBP = CPUAlpha* for the whole block */
    /* record the guest PC of this block so a host fault can be reported
     * in guest terms */
    mov_r_imm64(a, TA, pc);
    st_cpu(a, OFF_SCR1, TA);

    uint64_t cur = pc, fall = pc;
    int n = 0, done = 0;
    while (!done && n < 256) {
        if (j->xlat_hi && (cur < j->xlat_lo || cur >= j->xlat_hi)) break;
        uint32_t insn = *(const uint32_t *)(uintptr_t)cur;
        done = translate_insn(a, insn, cur, &fall);
        cur  = fall;
        n++;
    }
    if (!done) emit_exit(a, cur, EXIT_BLOCK_END);   /* block length cap */
    /* A block that never touched the FPU does not need to save MXCSR. */
    if (!g_fp_used) nop_fill(g_mx_slot, MXFORM_LEN);

    b->ninsn    = n;
    j->cache_ptr = a->p;
    size_t h = hash_pc(j, pc);
    b->hash_next = j->hash[h];
    j->hash[h] = b;
    return b;
}

void jit_run(JitCtx *j, CPUAlpha *cpu, uint64_t stop_lo, uint64_t stop_hi,
             uint64_t max_insn)
{
    for (;;) {
        if (cpu->pc < stop_lo || cpu->pc >= stop_hi) return;
        if (cpu->icount >= max_insn) { cpu->exit_code = EXIT_HALT; return; }
        TBlock *b = jit_lookup(j, cpu->pc);
        if (!b) b = jit_translate(j, cpu, cpu->pc);
        if (!b) { cpu->exit_code = EXIT_HALT; return; }
        ((BlockFn)b->code)(cpu);
        cpu->icount += b->ninsn;
        cpu->ireg[31] = 0;
        cpu->freg[31] = 0;
        if (cpu->exit_code == EXIT_UNIMPL) return;
    }
}

void jit_run_until(JitCtx *j, CPUAlpha *cpu, uint64_t stop_pc, uint64_t max_insn)
{
    for (;;) {
        if (cpu->pc == stop_pc) return;
        if (cpu->icount >= max_insn) { cpu->exit_code = EXIT_HALT; return; }
        TBlock *b = jit_lookup(j, cpu->pc);
        if (!b) b = jit_translate(j, cpu, cpu->pc);
        if (!b) { cpu->exit_code = EXIT_HALT; return; }
        ((BlockFn)b->code)(cpu);
        cpu->icount += b->ninsn;
        cpu->ireg[31] = 0;
        cpu->freg[31] = 0;
        if (cpu->exit_code == EXIT_UNIMPL || cpu->exit_code == EXIT_HALT) return;
    }
}
