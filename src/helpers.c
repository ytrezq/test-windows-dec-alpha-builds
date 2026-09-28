/* C helpers for Alpha instructions that are rare or awkward to inline:
 * the multimedia/byte-compare integer ops and the whole floating-point set.
 * qemu uses the same split; these can be inlined later if they ever get hot. */
#define _GNU_SOURCE
#include <math.h>
#include <fenv.h>
#include <float.h>
#include <string.h>
#include "emu.h"
#include "helpers.h"

static inline uint64_t rd_i(CPUAlpha *c, int r) { return r == 31 ? 0 : c->ireg[r]; }
static inline void     wr_i(CPUAlpha *c, int r, uint64_t v) { if (r != 31) c->ireg[r] = v; }
static inline uint64_t rd_f(CPUAlpha *c, int r) { return r == 31 ? 0 : c->freg[r]; }
static inline void     wr_f(CPUAlpha *c, int r, uint64_t v) { if (r != 31) c->freg[r] = v; }

static inline double   b2d(uint64_t b) { double d; memcpy(&d, &b, 8); return d; }
static inline uint64_t d2b(double d)   { uint64_t b; memcpy(&b, &d, 8); return b; }
static inline uint32_t f2b(float f)    { uint32_t b; memcpy(&b, &f, 4); return b; }
static inline float    b2f(uint32_t b) { float f; memcpy(&f, &b, 4); return f; }

/* A NaN operand is propagated (quieted, sign preserved); only a NaN that the
 * operation itself generates becomes the canonical positive quiet NaN. */
static inline uint64_t nan_t(uint64_t abits, uint64_t bbits, int use_a)
{
    if (use_a && isnan(b2d(abits))) return abits | (1ULL << 51);
    if (isnan(b2d(bbits)))          return bbits | (1ULL << 51);
    return 0x7FF8000000000000ULL;
}
static inline uint32_t nan_s(uint32_t am, uint32_t bm, int use_a)
{
    if (use_a && (am & 0x7F800000u) == 0x7F800000u && (am & 0x7FFFFFu))
        return am | 0x400000u;
    if ((bm & 0x7F800000u) == 0x7F800000u && (bm & 0x7FFFFFu))
        return bm | 0x400000u;
    return 0x7FC00000u;
}

/* S-format <-> T-format register conversions (the same bit layout LDS/STS
 * use).  The expanded exponent bits <61:59> are redundant and discarded. */
static inline float t_to_s(uint64_t a)
{ return b2f(((uint32_t)(a >> 32) & 0xC0000000u) | ((uint32_t)(a >> 29) & 0x3FFFFFFFu)); }
static inline uint64_t s_to_t_bits(uint32_t m)
{
    uint64_t sign = (uint64_t)(m >> 31) << 63;
    uint32_t exp8 = (m >> 23) & 0xFF;
    uint64_t frac = (uint64_t)(m & 0x7FFFFF) << 29;
    uint64_t exp11;
    /* The architectural bit-replication {e<7>,~e<7>x3,e<6:0>} equals a rebias
     * by 896 for normals, but zero and Inf/NaN are special cases. */
    if (exp8 == 0)         exp11 = 0;                   /* zero and S denormals
                                                         * keep the mantissa */
    else if (exp8 == 0xFF) exp11 = 0x7FF;               /* Inf / NaN */
    else                   exp11 = (uint64_t)exp8 + 896;
    return sign | (exp11 << 52) | frac;
}

/* ===================== integer helpers ================================= */
void helper_int_op(CPUAlpha *cpu, uint32_t insn)
{
    int op    = (int)(insn >> 26);
    int ra    = (int)((insn >> 21) & 31);
    int rb    = (int)((insn >> 16) & 31);
    int rc    = (int)(insn & 31);
    int func  = (int)((insn >> 5) & 0x7F);
    int islit = (int)((insn >> 12) & 1);
    int lit   = (int)((insn >> 13) & 0xFF);

    if (op == 0x18) {                       /* RPCC / RC / RS */
        unsigned mf = insn & 0xFFFF;
        if (mf == 0xC000) wr_i(cpu, ra, cpu->icount);   /* cycle counter */
        else              wr_i(cpu, ra, 0);
        return;
    }

    uint64_t av = rd_i(cpu, ra);
    uint64_t bv = islit ? (uint64_t)(unsigned)lit : rd_i(cpu, rb);

    if (op == 0x10 && func == 0x0F) {       /* CMPBGE */
        uint64_t r = 0;
        for (int i = 0; i < 8; i++) {
            unsigned x = (unsigned)((av >> (8 * i)) & 0xFF);
            unsigned y = (unsigned)((bv >> (8 * i)) & 0xFF);
            if (x >= y) r |= 1ULL << i;
        }
        wr_i(cpu, rc, r);
        return;
    }
    if (op == 0x12 && (func == 0x30 || func == 0x31)) {   /* ZAP / ZAPNOT */
        unsigned m = (unsigned)(bv & 0xFF);
        if (func == 0x30) m = ~m & 0xFF;
        uint64_t mask = 0;
        for (int i = 0; i < 8; i++) if (m & (1u << i)) mask |= 0xFFULL << (8 * i);
        wr_i(cpu, rc, av & mask);
        return;
    }
    if (op == 0x1C) {
        uint64_t r;
        switch (func) {
        case 0x31: { /* PERR: sum of absolute byte differences */
            r = 0;
            for (int i = 0; i < 8; i++) {
                int x = (int)((av >> (8 * i)) & 0xFF), y = (int)((bv >> (8 * i)) & 0xFF);
                r += (uint64_t)(x >= y ? x - y : y - x);
            }
            wr_i(cpu, rc, r); return;
        }
        case 0x34: /* UNPKBW */
            r = 0; for (int i = 0; i < 4; i++) r |= ((bv >> (8 * i)) & 0xFF) << (16 * i);
            wr_i(cpu, rc, r); return;
        case 0x35: /* UNPKBL */
            r = 0; for (int i = 0; i < 2; i++) r |= ((bv >> (8 * i)) & 0xFF) << (32 * i);
            wr_i(cpu, rc, r); return;
        case 0x36: /* PKWB */
            r = 0; for (int i = 0; i < 4; i++) r |= ((bv >> (16 * i)) & 0xFF) << (8 * i);
            wr_i(cpu, rc, r); return;
        case 0x37: /* PKLB */
            r = 0; for (int i = 0; i < 2; i++) r |= ((bv >> (32 * i)) & 0xFF) << (8 * i);
            wr_i(cpu, rc, r); return;
        case 0x38: case 0x39: case 0x3A: case 0x3B: { /* MINSB8 MINSW4 MINUB8 MINUW4 */
            r = 0;
            if (func == 0x38) for (int i = 0; i < 8; i++) {
                int8_t x = (int8_t)(av >> (8*i)), y = (int8_t)(bv >> (8*i));
                r |= (uint64_t)(uint8_t)(x < y ? x : y) << (8*i);
            } else if (func == 0x3A) for (int i = 0; i < 8; i++) {
                uint8_t x = (uint8_t)(av >> (8*i)), y = (uint8_t)(bv >> (8*i));
                r |= (uint64_t)(x < y ? x : y) << (8*i);
            } else if (func == 0x39) for (int i = 0; i < 4; i++) {
                int16_t x = (int16_t)(av >> (16*i)), y = (int16_t)(bv >> (16*i));
                r |= (uint64_t)(uint16_t)(x < y ? x : y) << (16*i);
            } else for (int i = 0; i < 4; i++) {
                uint16_t x = (uint16_t)(av >> (16*i)), y = (uint16_t)(bv >> (16*i));
                r |= (uint64_t)(x < y ? x : y) << (16*i);
            }
            wr_i(cpu, rc, r); return;
        }
        case 0x3C: case 0x3D: case 0x3E: case 0x3F: { /* MAXUB8 MAXUW4 MAXSB8 MAXSW4 */
            r = 0;
            if (func == 0x3E) for (int i = 0; i < 8; i++) {
                int8_t x = (int8_t)(av >> (8*i)), y = (int8_t)(bv >> (8*i));
                r |= (uint64_t)(uint8_t)(x > y ? x : y) << (8*i);
            } else if (func == 0x3C) for (int i = 0; i < 8; i++) {
                uint8_t x = (uint8_t)(av >> (8*i)), y = (uint8_t)(bv >> (8*i));
                r |= (uint64_t)(x > y ? x : y) << (8*i);
            } else if (func == 0x3F) for (int i = 0; i < 4; i++) {
                int16_t x = (int16_t)(av >> (16*i)), y = (int16_t)(bv >> (16*i));
                r |= (uint64_t)(uint16_t)(x > y ? x : y) << (16*i);
            } else for (int i = 0; i < 4; i++) {
                uint16_t x = (uint16_t)(av >> (16*i)), y = (uint16_t)(bv >> (16*i));
                r |= (uint64_t)(x > y ? x : y) << (16*i);
            }
            wr_i(cpu, rc, r); return;
        }
        case 0x78: /* FTOIS : S-format bits of Fa -> sign-extended longword */
        {
            uint64_t f = rd_f(cpu, ra);
            uint32_t s = (uint32_t)(((f >> 63) << 31) | (((f >> 62) & 1) << 30) |
                                    (((f >> 52) & 0x7F) << 23) | ((f >> 29) & 0x7FFFFF));
            wr_i(cpu, rc, (uint64_t)(int64_t)(int32_t)s); return;
        }
        default: break;
        }
    }
    cpu->exit_code = EXIT_UNIMPL;
    cpu->pc -= 4;               /* report the offending instruction */
}

/* ===================== floating point ================================== */
/* Rounding: 0 = /C chopped, 1 = /M -inf, 2 = normal (nearest-even),
 *           3 = /D dynamic (FPCR<59:58>).  The encoding is the same for
 *           every qualified form (verified against the assembler).      */
static int eff_round(CPUAlpha *cpu, int rnd)
{ return rnd == 3 ? (int)((cpu->fpcr >> 58) & 3) : rnd; }

/* Drive the host FPU with the Alpha rounding mode so that both the
 * arithmetic and the narrowing to single precision round identically. */
static int host_round(int r)
{
    switch (r) {
    case 0: return FE_TOWARDZERO;
    case 1: return FE_DOWNWARD;
    case 3: return FE_UPWARD;
    default: return FE_TONEAREST;
    }
}

/* CVTTQ out-of-range / NaN behaviour follows the modulo conversion that
 * qemu (and the hardware's non-trapping path) produce. */
static int64_t f2i_modulo(double v)
{
    if (!isfinite(v)) return 0;      /* NaN and +/-Inf both yield 0 */
    double t = trunc(v);
    if (t >= -9223372036854775808.0 && t < 9223372036854775808.0)
        return (int64_t)t;
    double m = fmod(t, 18446744073709551616.0);
    if (m >= 9223372036854775808.0)  m -= 18446744073709551616.0;
    if (m < -9223372036854775808.0)  m += 18446744073709551616.0;
    return (int64_t)m;
}

void helper_fp_op(CPUAlpha *cpu, uint32_t insn)
{
    int op   = (int)(insn >> 26);
    int fa   = (int)((insn >> 21) & 31);
    int fb   = (int)((insn >> 16) & 31);
    int fc   = (int)(insn & 31);
    int func = (int)((insn >> 5) & 0x7FF);

    uint64_t abits = rd_f(cpu, fa), bbits = rd_f(cpu, fb);
    double   a = b2d(abits), b = b2d(bbits);

    if (op == 0x17) {                       /* FLTL: bit manipulation */
        switch (func) {
        case 0x020: wr_f(cpu, fc, (abits & (1ULL << 63)) | (bbits & ~(1ULL << 63))); return; /* CPYS */
        case 0x021: wr_f(cpu, fc, ((~abits) & (1ULL << 63)) | (bbits & ~(1ULL << 63))); return; /* CPYSN */
        case 0x022: wr_f(cpu, fc, (abits & 0xFFF0000000000000ULL) | (bbits & 0x000FFFFFFFFFFFFFULL)); return; /* CPYSE */
        case 0x024: cpu->fpcr = abits; return;                 /* MT_FPCR */
        case 0x025: wr_f(cpu, fa, cpu->fpcr); return;          /* MF_FPCR */
        case 0x010: { /* CVTLQ : Fb<63:62>||Fb<58:29> sign-extended */
            uint32_t v = (uint32_t)((((bbits >> 62) & 3) << 30) | ((bbits >> 29) & 0x3FFFFFFF));
            wr_f(cpu, fc, (uint64_t)(int64_t)(int32_t)v); return;
        }
        case 0x030: case 0x130: case 0x530: { /* CVTQL (+/V,/SV) */
            uint64_t v = bbits;
            wr_f(cpu, fc, (((v >> 30) & 3) << 62) | ((v & 0x3FFFFFFF) << 29)); return;
        }
        case 0x02A: case 0x02B: case 0x02C: case 0x02D: case 0x02E: case 0x02F: {
            uint64_t nz = abits << 1;                 /* value, sign removed */
            int neg = (int64_t)abits < 0, zero = nz == 0, take;
            switch (func) {
            case 0x02A: take = zero; break;                    /* FCMOVEQ */
            case 0x02B: take = !zero; break;                   /* FCMOVNE */
            case 0x02C: take = neg && !zero; break;            /* FCMOVLT */
            case 0x02D: take = !neg || zero; break;            /* FCMOVGE */
            case 0x02E: take = neg || zero; break;             /* FCMOVLE */
            default:    take = !neg && !zero; break;           /* FCMOVGT */
            }
            if (take) wr_f(cpu, fc, bbits);
            return;
        }
        default: break;
        }
        cpu->exit_code = EXIT_UNIMPL; cpu->pc -= 4; return;
    }

    if (op == 0x14) {                       /* ITFP */
        switch (func & 0x3F) {
        case 0x04: { /* ITOFS : integer bits -> S value */
            wr_f(cpu, fc, s_to_t_bits((uint32_t)rd_i(cpu, fa))); return;
        }
        case 0x24: wr_f(cpu, fc, rd_i(cpu, fa)); return;           /* ITOFT */
        case 0x0B: { float v = sqrtf(t_to_s(bbits));
                   wr_f(cpu, fc, s_to_t_bits(isnan(v)
                        ? nan_s(0, f2b(t_to_s(bbits)), 0) : f2b(v))); return; } /* SQRTS */
        case 0x2B: { double v=sqrt(b);
                   wr_f(cpu, fc, isnan(v) ? nan_t(0, bbits, 0) : d2b(v)); return; } /* SQRTT */
        default: break;
        }
        cpu->exit_code = EXIT_UNIMPL; cpu->pc -= 4; return;
    }

    /* op == 0x16 : IEEE arithmetic.  base6/rnd are valid for every
     * qualified form; the trap-mode bits select CVTST over CVTTS.     */
    int base = func & 0x3F;
    int rnd  = eff_round(cpu, (func >> 6) & 3);
    int trp  = (func >> 8) & 7;
    /* S-format operations do NOT read the register as a double: they extract
     * the single from bits <63:62>||<58:29>, discarding the expanded exponent
     * bits <61:59>, compute in float32, and re-expand.  Treating the register
     * as a double gives different answers whenever the exponent lies outside
     * the single-precision range. */
    int isS  = (base & 0x20) == 0;
    int save = fegetround();
    fesetround(host_round(rnd));
    double r = 0;
    float  fr = 0;
    int done = 1;

    /* CVTQS (base6 0x3c) produces a single even though bit 0x20 is set. */
    if (isS || base == 0x3c) {
        float fa_ = t_to_s(abits), fb_ = t_to_s(bbits);
        switch (base & 0x1F) {
        case 0x00: fr = fa_ + fb_; break;
        case 0x01: fr = fa_ - fb_; break;
        case 0x02: fr = fa_ * fb_; break;
        case 0x03: fr = fa_ / fb_; break;
        case 0x1C: fr = (float)(int64_t)bbits; break;              /* CVTQS */
        default:
            fesetround(save);
            cpu->exit_code = EXIT_UNIMPL; cpu->pc -= 4; return;
        }
        fesetround(save);
        wr_f(cpu, fc, s_to_t_bits(isnan(fr)
                 ? nan_s(f2b(fa_), f2b(fb_), (base & 0x1F) <= 0x03) : f2b(fr)));
        return;
    }

    switch (base & 0x1F) {
    case 0x00: r = a + b; break;                                   /* ADDT */
    case 0x01: r = a - b; break;                                   /* SUBT */
    case 0x02: r = a * b; break;                                   /* MULT */
    case 0x03: r = a / b; break;                                   /* DIVT */
    case 0x0B: r = sqrt(b); break;                                 /* SQRTT */
    case 0x04: wr_f(cpu, fc, (isnan(a) || isnan(b)) ? 0x4000000000000000ULL : 0);
               done = 0; break;                                    /* CMPTUN */
    case 0x05: wr_f(cpu, fc, (a == b) ? 0x4000000000000000ULL : 0); done = 0; break;
    case 0x06: wr_f(cpu, fc, (a <  b) ? 0x4000000000000000ULL : 0); done = 0; break;
    case 0x07: wr_f(cpu, fc, (a <= b) ? 0x4000000000000000ULL : 0); done = 0; break;
    case 0x0C:
        if ((trp & 3) == 2) {              /* CVTST : widen the single *
                                            * (func 0x2AC and 0x6AC)    */
            fesetround(save);
            wr_f(cpu, fc, d2b((double)t_to_s(bbits)));
            return;
        }
        {                                  /* CVTTS : narrow T to S */
            float v = (float)b;
            fesetround(save);
            wr_f(cpu, fc, s_to_t_bits(isnan(v)
                     ? (uint32_t)(((bbits >> 32) & 0x80000000u) | 0x7FC00000u
                                  | (uint32_t)((bbits >> 29) & 0x3FFFFFu))
                     : f2b(v)));
            return;
        }
    case 0x0F: /* CVTTQ : float -> 64-bit integer held in the register */
        wr_f(cpu, fc, (uint64_t)f2i_modulo(nearbyint(b)));
        done = 0; break;
    case 0x1E: r = (double)(int64_t)bbits; break;                  /* CVTQT */
    default:
        fesetround(save);
        cpu->exit_code = EXIT_UNIMPL; cpu->pc -= 4; return;
    }
    if (done) {
        /* Alpha delivers the canonical positive quiet NaN; x86 would give
         * the negative one for e.g. sqrt(-1). */
        /* Alpha flushes a denormal result to zero when underflow traps are
         * disabled; x86 would deliver the subnormal. */
        if (r != 0.0 && isfinite(r) && fabs(r) < DBL_MIN) r = copysign(0.0, r);
        wr_f(cpu, fc, isnan(r) ? nan_t(abits, bbits, (base & 0x1F) <= 0x03) : d2b(r));
    }
    fesetround(save);
}

/* LDS / STS use the architectural S<->T bit expansion (exact, including
 * denormals and NaN payloads) rather than a host conversion. */
void helper_fp_mem(CPUAlpha *cpu, uint32_t insn)
{
    int op = (int)(insn >> 26);
    int ra = (int)((insn >> 21) & 31);
    int rb = (int)((insn >> 16) & 31);
    int64_t disp = (int64_t)(int16_t)(insn & 0xFFFF);
    uint64_t va = rd_i(cpu, rb) + (uint64_t)disp;

    if (op == 0x22) {                                   /* LDS */
        uint32_t m;
        memcpy(&m, (void *)(uintptr_t)va, 4);
        wr_f(cpu, ra, s_to_t_bits(m));
        return;
    }
    if (op == 0x26) {                                   /* STS */
        uint64_t f = rd_f(cpu, ra);
        uint32_t m = (uint32_t)(((f >> 63) << 31) | (((f >> 62) & 1) << 30) |
                                (((f >> 52) & 0x7F) << 23) | ((f >> 29) & 0x7FFFFF));
        memcpy((void *)(uintptr_t)va, &m, 4);
        return;
    }
    cpu->exit_code = EXIT_UNIMPL;   /* VAX F/G formats: never emitted by MSVC */
    cpu->pc -= 4;
}

/* Default call-gate handler: the differential-test driver has no native
 * bindings, so PALcode-space instructions are simply unimplemented there.
 * axpwin provides a strong definition that dispatches to the bottom layer. */
__attribute__((weak)) void helper_native(CPUAlpha *cpu, uint32_t insn)
{
    (void)insn;
    cpu->exit_code = EXIT_UNIMPL;
}
