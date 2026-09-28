/* Minimal x86-64 machine-code emitter used by the Alpha translator. */
#ifndef AXP64EMU_X86EMIT_H
#define AXP64EMU_X86EMIT_H

#include <stdint.h>
#include <string.h>

/* host register numbers */
enum { RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7,
       R8=8, R9=9, R10=10, R11=11, R12=12, R13=13, R14=14, R15=15 };

/* RBP permanently holds the CPUAlpha* while inside generated code. */
#define CPUREG RBP

typedef struct { uint8_t *p; uint8_t *end; } Asm;

static inline void ab(Asm *a, uint8_t v)  { *a->p++ = v; }
static inline void aw(Asm *a, uint16_t v) { memcpy(a->p, &v, 2); a->p += 2; }
static inline void ad(Asm *a, uint32_t v) { memcpy(a->p, &v, 4); a->p += 4; }
static inline void aq(Asm *a, uint64_t v) { memcpy(a->p, &v, 8); a->p += 8; }

/* REX.W with optional reg/rm extensions */
static inline void rexw(Asm *a, int reg, int rm)
{ ab(a, (uint8_t)(0x48 | (((reg >> 3) & 1) << 2) | ((rm >> 3) & 1))); }
/* REX without W (needed for byte regs / 32-bit ops touching r8..r15) */
static inline void rex0(Asm *a, int reg, int rm)
{
    uint8_t v = (uint8_t)(0x40 | (((reg >> 3) & 1) << 2) | ((rm >> 3) & 1));
    if (v != 0x40) ab(a, v);
}
static inline void modrm_rr(Asm *a, int reg, int rm)
{ ab(a, (uint8_t)(0xC0 | ((reg & 7) << 3) | (rm & 7))); }

/* [base + disp32] */
static inline void modrm_md(Asm *a, int reg, int base, int32_t disp)
{
    ab(a, (uint8_t)(0x80 | ((reg & 7) << 3) | (base & 7)));
    if ((base & 7) == RSP) ab(a, 0x24);       /* SIB for rsp/r12 base */
    ad(a, (uint32_t)disp);
}

/* ---- 64-bit moves ---------------------------------------------------- */
static inline void mov_r_m(Asm *a, int dst, int base, int32_t disp)
{ rexw(a, dst, base); ab(a, 0x8B); modrm_md(a, dst, base, disp); }
static inline void mov_m_r(Asm *a, int base, int32_t disp, int src)
{ rexw(a, src, base); ab(a, 0x89); modrm_md(a, src, base, disp); }
static inline void mov_r_r(Asm *a, int dst, int src)
{ rexw(a, src, dst); ab(a, 0x89); modrm_rr(a, src, dst); }
static inline void mov_r_imm64(Asm *a, int dst, uint64_t imm)
{
    if (imm == 0) { /* xor r32,r32 */ rex0(a, dst, dst); ab(a, 0x31); modrm_rr(a, dst, dst); return; }
    if (imm <= 0xFFFFFFFFull) {        /* mov r32, imm32 zero-extends */
        rex0(a, 0, dst); ab(a, (uint8_t)(0xB8 | (dst & 7))); ad(a, (uint32_t)imm); return;
    }
    rexw(a, 0, dst); ab(a, (uint8_t)(0xB8 | (dst & 7))); aq(a, imm);
}

/* ---- CPU-state accessors (base = RBP) -------------------------------- */
static inline void ld_cpu(Asm *a, int dst, int32_t off)  { mov_r_m(a, dst, CPUREG, off); }
static inline void st_cpu(Asm *a, int32_t off, int src)  { mov_m_r(a, CPUREG, off, src); }

/* ---- ALU ------------------------------------------------------------- */
/* opcodes for "op r/m64, r64" form */
enum { X_ADD=0x01, X_OR=0x09, X_AND=0x21, X_SUB=0x29, X_XOR=0x31, X_CMP=0x39 };
/* /digit for "op r/m64, imm32" (group 0x81) */
enum { D_ADD=0, D_OR=1, D_AND=4, D_SUB=5, D_XOR=6, D_CMP=7 };

static inline void alu_rr(Asm *a, int op, int dst_rm, int src)
{ rexw(a, src, dst_rm); ab(a, (uint8_t)op); modrm_rr(a, src, dst_rm); }
static inline void alu_ri(Asm *a, int digit, int dst, int32_t imm)
{ rexw(a, 0, dst); ab(a, 0x81); modrm_rr(a, digit, dst); ad(a, (uint32_t)imm); }
static inline void not_r(Asm *a, int dst)
{ rexw(a, 0, dst); ab(a, 0xF7); modrm_rr(a, 2, dst); }
static inline void neg_r(Asm *a, int dst)
{ rexw(a, 0, dst); ab(a, 0xF7); modrm_rr(a, 3, dst); }

/* lea dst, [base + index*scale + disp32] */
static inline void lea_isd(Asm *a, int dst, int base, int index, int scale, int32_t disp)
{
    int ss = scale == 8 ? 3 : scale == 4 ? 2 : scale == 2 ? 1 : 0;
    ab(a, (uint8_t)(0x48 | (((dst >> 3) & 1) << 2) | (((index >> 3) & 1) << 1) | ((base >> 3) & 1)));
    ab(a, 0x8D);
    ab(a, (uint8_t)(0x80 | ((dst & 7) << 3) | 4));          /* mod=10, rm=SIB */
    ab(a, (uint8_t)((ss << 6) | ((index & 7) << 3) | (base & 7)));
    ad(a, (uint32_t)disp);
}

/* ---- shifts ---------------------------------------------------------- */
enum { S_SHL=4, S_SHR=5, S_SAR=7 };
static inline void shift_cl(Asm *a, int digit, int dst)
{ rexw(a, 0, dst); ab(a, 0xD3); modrm_rr(a, digit, dst); }
static inline void shift_imm(Asm *a, int digit, int dst, uint8_t n)
{ rexw(a, 0, dst); ab(a, 0xC1); modrm_rr(a, digit, dst); ab(a, n); }
/* 32-bit shift (for sign-extended 32-bit Alpha ops) */
static inline void shift32_imm(Asm *a, int digit, int dst, uint8_t n)
{ rex0(a, 0, dst); ab(a, 0xC1); modrm_rr(a, digit, dst); ab(a, n); }

/* ---- extensions ------------------------------------------------------ */
static inline void movzx_b(Asm *a, int dst, int src)  /* movzbq */
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xB6); modrm_rr(a, dst, src); }
static inline void movzx_w(Asm *a, int dst, int src)
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xB7); modrm_rr(a, dst, src); }
static inline void movsx_b(Asm *a, int dst, int src)
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xBE); modrm_rr(a, dst, src); }
static inline void movsx_w(Asm *a, int dst, int src)
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xBF); modrm_rr(a, dst, src); }
static inline void movsxd_r(Asm *a, int dst, int src) /* movslq */
{ rexw(a, dst, src); ab(a, 0x63); modrm_rr(a, dst, src); }

/* 32-bit ALU (result must then be sign-extended for Alpha *L ops) */
static inline void alu32_rr(Asm *a, int op, int dst_rm, int src)
{ rex0(a, src, dst_rm); ab(a, (uint8_t)op); modrm_rr(a, src, dst_rm); }

/* ---- memory access through a guest pointer (identity mapping) -------- */
static inline void ldq_via(Asm *a, int dst, int base, int32_t disp)
{ rexw(a, dst, base); ab(a, 0x8B); modrm_md(a, dst, base, disp); }
static inline void ldl_via(Asm *a, int dst, int base, int32_t disp) /* movslq */
{ rexw(a, dst, base); ab(a, 0x63); modrm_md(a, dst, base, disp); }
static inline void ldbu_via(Asm *a, int dst, int base, int32_t disp)
{ rexw(a, dst, base); ab(a, 0x0F); ab(a, 0xB6); modrm_md(a, dst, base, disp); }
static inline void ldwu_via(Asm *a, int dst, int base, int32_t disp)
{ rexw(a, dst, base); ab(a, 0x0F); ab(a, 0xB7); modrm_md(a, dst, base, disp); }
static inline void stq_via(Asm *a, int base, int32_t disp, int src)
{ rexw(a, src, base); ab(a, 0x89); modrm_md(a, src, base, disp); }
static inline void stl_via(Asm *a, int base, int32_t disp, int src)
{ rex0(a, src, base); ab(a, 0x89); modrm_md(a, src, base, disp); }
static inline void stw_via(Asm *a, int base, int32_t disp, int src)
{ ab(a, 0x66); rex0(a, src, base); ab(a, 0x89); modrm_md(a, src, base, disp); }
static inline void stb_via(Asm *a, int base, int32_t disp, int src)
{ rex0(a, src, base); if ((0x40|(((src>>3)&1)<<2)|((base>>3)&1)) == 0x40 && src >= RSP) ab(a, 0x40);
  ab(a, 0x88); modrm_md(a, src, base, disp); }

/* ---- control flow ---------------------------------------------------- */
enum { CC_O=0, CC_NO=1, CC_B=2, CC_AE=3, CC_E=4, CC_NE=5, CC_BE=6, CC_A=7,
       CC_S=8, CC_NS=9, CC_P=10, CC_NP=11, CC_L=12, CC_GE=13, CC_LE=14, CC_G=15 };

static inline void test_rr(Asm *a, int r1, int r2)
{ rexw(a, r2, r1); ab(a, 0x85); modrm_rr(a, r2, r1); }
static inline void cmp_ri(Asm *a, int r, int32_t imm) { alu_ri(a, D_CMP, r, imm); }
static inline void setcc_r(Asm *a, int cc, int r)
{ rex0(a, 0, r); if (r >= RSP && r < R8) ab(a, 0x40); ab(a, 0x0F); ab(a, (uint8_t)(0x90 | cc)); modrm_rr(a, 0, r); }
static inline void cmov_rr(Asm *a, int cc, int dst, int src)
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, (uint8_t)(0x40 | cc)); modrm_rr(a, dst, src); }

/* emit jcc rel32, return address of the rel32 field for later patching */
static inline uint32_t *jcc_rel32(Asm *a, int cc)
{ ab(a, 0x0F); ab(a, (uint8_t)(0x80 | cc)); uint32_t *slot = (uint32_t *)a->p; ad(a, 0); return slot; }
static inline uint32_t *jmp_rel32(Asm *a)
{ ab(a, 0xE9); uint32_t *slot = (uint32_t *)a->p; ad(a, 0); return slot; }
static inline void patch_rel32(uint32_t *slot, uint8_t *target)
{ *slot = (uint32_t)(int32_t)(target - ((uint8_t *)slot + 4)); }
static inline void ret_(Asm *a) { ab(a, 0xC3); }

/* popcnt / lzcnt / tzcnt (host has ABM+BMI1, verified at build time) */
static inline void popcnt_rr(Asm *a, int dst, int src)
{ ab(a, 0xF3); rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xB8); modrm_rr(a, dst, src); }
static inline void lzcnt_rr(Asm *a, int dst, int src)
{ ab(a, 0xF3); rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xBD); modrm_rr(a, dst, src); }
static inline void tzcnt_rr(Asm *a, int dst, int src)
{ ab(a, 0xF3); rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xBC); modrm_rr(a, dst, src); }

/* imul dst, src (signed low 64) */
static inline void imul_rr(Asm *a, int dst, int src)
{ rexw(a, dst, src); ab(a, 0x0F); ab(a, 0xAF); modrm_rr(a, dst, src); }
/* mul r/m64 -> RDX:RAX (unsigned) */
static inline void mul_r(Asm *a, int src)
{ rexw(a, 0, src); ab(a, 0xF7); modrm_rr(a, 4, src); }

/* push/pop (for host register preservation) */
static inline void push_r(Asm *a, int r) { if (r >= R8) ab(a, 0x41); ab(a, (uint8_t)(0x50 | (r & 7))); }
static inline void pop_r(Asm *a, int r)  { if (r >= R8) ab(a, 0x41); ab(a, (uint8_t)(0x58 | (r & 7))); }

/* ====================== SSE / SSE2 / SSSE3 / SSE4.1 ====================== *
 * The Alpha multimedia (MVI) instructions and the whole floating-point set
 * are translated to real x86-64 SIMD instructions rather than calls into C.
 * XMM0..XMM3 are used as scratch: they are caller-saved in both the SysV
 * and the Win64 ABIs, so a translated block may clobber them freely.
 * XMM register numbers reuse the GPR numbering, so modrm_rr/modrm_md and the
 * REX helpers work unchanged.                                              */
enum { X0=0, X1=1, X2=2, X3=3, X4=4, X5=5, X6=6, X7=7 };

/* [66|F2|F3] [REX] 0F <op> /r   (register form)                            */
static inline void sse_rr(Asm *a, uint8_t pfx, uint8_t op, int reg, int rm)
{ if (pfx) ab(a, pfx); rex0(a, reg, rm); ab(a, 0x0F); ab(a, op); modrm_rr(a, reg, rm); }
/* same, but with REX.W (movq r64<->xmm, cvtsi2sd, cvttsd2si, ...)          */
static inline void sse_rr_w(Asm *a, uint8_t pfx, uint8_t op, int reg, int rm)
{ if (pfx) ab(a, pfx); rexw(a, reg, rm); ab(a, 0x0F); ab(a, op); modrm_rr(a, reg, rm); }
/* [66|F2|F3] [REX] 0F <op> /r with a [base+disp32] operand                 */
static inline void sse_rm(Asm *a, uint8_t pfx, uint8_t op, int reg, int base, int32_t disp)
{ if (pfx) ab(a, pfx); rex0(a, reg, base); ab(a, 0x0F); ab(a, op); modrm_md(a, reg, base, disp); }
/* [66] [REX] 0F 38 <op> /r      (SSSE3 / SSE4.1)                           */
static inline void sse38_rr(Asm *a, uint8_t pfx, uint8_t op, int reg, int rm)
{ if (pfx) ab(a, pfx); rex0(a, reg, rm); ab(a, 0x0F); ab(a, 0x38); ab(a, op); modrm_rr(a, reg, rm); }
/* shift-by-immediate group: 66 0F <grp> /digit ib                          */
static inline void sse_shift_i(Asm *a, uint8_t grp, int digit, int xm, uint8_t n)
{ ab(a, 0x66); rex0(a, digit, xm); ab(a, 0x0F); ab(a, grp); modrm_rr(a, digit, xm); ab(a, n); }
/* compare with an imm8 predicate: [F2|F3] 0F C2 /r ib                      */
static inline void sse_cmp_i(Asm *a, uint8_t pfx, int xd, int xs, uint8_t pred)
{ sse_rr(a, pfx, 0xC2, xd, xs); ab(a, pred); }

/* ---- moves ----------------------------------------------------------- */
#define movq_x_r(a,x,r)      sse_rr_w(a, 0x66, 0x6E, x, r)   /* xmm <- r64  */
#define movq_r_x(a,r,x)      sse_rr_w(a, 0x66, 0x7E, x, r)   /* r64 <- xmm  */
#define movd_x_r(a,x,r)      sse_rr  (a, 0x66, 0x6E, x, r)   /* xmm <- r32  */
#define movd_r_x(a,r,x)      sse_rr  (a, 0x66, 0x7E, x, r)   /* r32 <- xmm  */
#define movaps_x_x(a,d,s)    sse_rr  (a, 0x00, 0x28, d, s)
#define movq_x_x(a,d,s)      sse_rr  (a, 0xF3, 0x7E, d, s)   /* low 64, zeroed hi */
#define movq_x_m(a,x,b,o)    sse_rm  (a, 0xF3, 0x7E, x, b, o)
#define movq_m_x(a,b,o,x)    sse_rm  (a, 0x66, 0xD6, x, b, o)
#define movd_x_m(a,x,b,o)    sse_rm  (a, 0x66, 0x6E, x, b, o)
#define movd_m_x(a,b,o,x)    sse_rm  (a, 0x66, 0x7E, x, b, o)
#define pxor_x_x(a,d,s)      sse_rr  (a, 0x66, 0xEF, d, s)

/* ---- packed integer (SSE2) ------------------------------------------- */
#define psadbw(a,d,s)        sse_rr(a, 0x66, 0xF6, d, s)
#define pminub(a,d,s)        sse_rr(a, 0x66, 0xDA, d, s)
#define pmaxub(a,d,s)        sse_rr(a, 0x66, 0xDE, d, s)
#define pminsw(a,d,s)        sse_rr(a, 0x66, 0xEA, d, s)
#define pmaxsw(a,d,s)        sse_rr(a, 0x66, 0xEE, d, s)
#define pcmpeqb(a,d,s)       sse_rr(a, 0x66, 0x74, d, s)
#define punpcklbw(a,d,s)     sse_rr(a, 0x66, 0x60, d, s)
#define punpcklwd(a,d,s)     sse_rr(a, 0x66, 0x61, d, s)
#define packuswb(a,d,s)      sse_rr(a, 0x66, 0x67, d, s)
#define pand_x(a,d,s)        sse_rr(a, 0x66, 0xDB, d, s)
#define psubusw(a,d,s)       sse_rr(a, 0x66, 0xD9, d, s)
#define psubw_x(a,d,s)       sse_rr(a, 0x66, 0xF9, d, s)
#define paddw_x(a,d,s)       sse_rr(a, 0x66, 0xFD, d, s)
#define pmovmskb(a,r,x)      sse_rr(a, 0x66, 0xD7, r, x)     /* r32 <- mask */
#define psrlq_i(a,x,n)       sse_shift_i(a, 0x73, 2, x, n)
#define psllq_i(a,x,n)       sse_shift_i(a, 0x73, 6, x, n)
#define psrld_i(a,x,n)       sse_shift_i(a, 0x72, 2, x, n)
#define pslld_i(a,x,n)       sse_shift_i(a, 0x72, 6, x, n)

/* ---- SSE4.1 / SSSE3 (guarded by a CPUID probe at jit_init) ------------ */
#define pminsb(a,d,s)        sse38_rr(a, 0x66, 0x38, d, s)
#define pminuw(a,d,s)        sse38_rr(a, 0x66, 0x3A, d, s)
#define pmaxsb(a,d,s)        sse38_rr(a, 0x66, 0x3C, d, s)
#define pmaxuw(a,d,s)        sse38_rr(a, 0x66, 0x3E, d, s)

/* ---- scalar floating point (SSE2) ------------------------------------- */
#define addsd(a,d,s)         sse_rr(a, 0xF2, 0x58, d, s)
#define subsd(a,d,s)         sse_rr(a, 0xF2, 0x5C, d, s)
#define mulsd(a,d,s)         sse_rr(a, 0xF2, 0x59, d, s)
#define divsd(a,d,s)         sse_rr(a, 0xF2, 0x5E, d, s)
#define sqrtsd(a,d,s)        sse_rr(a, 0xF2, 0x51, d, s)
#define addss(a,d,s)         sse_rr(a, 0xF3, 0x58, d, s)
#define subss(a,d,s)         sse_rr(a, 0xF3, 0x5C, d, s)
#define mulss(a,d,s)         sse_rr(a, 0xF3, 0x59, d, s)
#define divss(a,d,s)         sse_rr(a, 0xF3, 0x5E, d, s)
#define sqrtss(a,d,s)        sse_rr(a, 0xF3, 0x51, d, s)
#define cvtsd2ss(a,d,s)      sse_rr(a, 0xF2, 0x5A, d, s)
#define cvtss2sd(a,d,s)      sse_rr(a, 0xF3, 0x5A, d, s)
#define cmpsd_i(a,d,s,p)     sse_cmp_i(a, 0xF2, d, s, p)
#define cmpss_i(a,d,s,p)     sse_cmp_i(a, 0xF3, d, s, p)
#define andps_x(a,d,s)       sse_rr(a, 0x00, 0x54, d, s)
#define andnps_x(a,d,s)      sse_rr(a, 0x00, 0x55, d, s)   /* d = ~d & s   */
#define cvtsi2sd(a,x,r)      sse_rr_w(a, 0xF2, 0x2A, x, r) /* xmm <- r64   */
#define cvtsi2ss(a,x,r)      sse_rr_w(a, 0xF3, 0x2A, x, r)
#define cvtsd2si(a,r,x)      sse_rr_w(a, 0xF2, 0x2D, r, x) /* r64 <- xmm, MXCSR rounding */
#define ucomisd_x(a,d,s)     sse_rr(a, 0x66, 0x2E, d, s)   /* PF set if unordered */
#define ucomiss_x(a,d,s)     sse_rr(a, 0x00, 0x2E, d, s)
/* cmpsd/cmpss predicates */
enum { CMP_EQ=0, CMP_LT=1, CMP_LE=2, CMP_UNORD=3, CMP_NEQ=4, CMP_ORD=7 };

/* ---- MXCSR ----------------------------------------------------------- */
static inline void stmxcsr_m(Asm *a, int base, int32_t disp)
{ ab(a, 0x0F); ab(a, 0xAE); modrm_md(a, 3, base, disp); }
static inline void ldmxcsr_m(Asm *a, int base, int32_t disp)
{ ab(a, 0x0F); ab(a, 0xAE); modrm_md(a, 2, base, disp); }
/* the two forms above are 8 bytes each when base is rsp; this is the
 * equivalent-length nop used to patch the save out of an FP-free block */
#define MXFORM_LEN 8
static inline void nop_fill(uint8_t *p, size_t n)
{   /* 0F 1F 84 00 xx xx xx xx : 8-byte canonical multi-byte nop */
    static const uint8_t n8[8] = { 0x0F,0x1F,0x84,0x00,0,0,0,0 };
    while (n >= 8) { memcpy(p, n8, 8); p += 8; n -= 8; }
    while (n--) *p++ = 0x90;
}

/* 32-bit zero-extending load: mov r32, [base+disp32] */
static inline void ldlu_via(Asm *a, int dst, int base, int32_t disp)
{ rex0(a, dst, base); ab(a, 0x8B); modrm_md(a, dst, base, disp); }


#endif
