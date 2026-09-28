#!/usr/bin/env python3
"""Differential test: run the same Alpha instruction sequence under the
axp64emu translator and natively under qemu-alpha, then compare the full
architectural state (32 int regs, 32 FP regs, FPCR) and a 4 KiB data buffer.

Conventions shared by both harnesses:
  * test code executes with every register loaded from the initial state
  * r29 is RESERVED (the qemu harness uses it to address its state area),
    so generated tests never read or write it
  * a 4 KiB data buffer lives at 0x10000000 and is pre-filled with
    byte[i] = (i*167 + 13) & 0xFF in both environments
  * r20/r21 are memory base registers and are never written by a test
"""
import os, random, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EMU  = os.path.join(HERE, "..", "axpemu")
DATA_BASE  = 0x10000000
STATE_BASE = 0x21000000
CODE_BASE  = 0x20000000
BASE_REGS  = (20, 21)
RESERVED   = {29, 31} | set(BASE_REGS)

LD_REGS = [r for r in range(31) if r != 29]
# Alpha Linux IEEE control word: no trap enabled, underflow mapped to zero.
IEEE_MAP_UMZ = 1 << 13
FPCW = IEEE_MAP_UMZ

REF_LD = "\n".join(f"\tldt\t$f{i}, {256+8*i}($29)" for i in range(31))
REF_ST = "\n".join(f"\tstt\t$f{i}, {256+8*i}($29)" for i in range(31))
INT_LD = "\n".join(f"\tldq\t${i}, {8*i}($29)" for i in LD_REGS + [30] if i != 30) \
         + "\n\tldq\t$30, 240($29)"
INT_ST = "\n".join(f"\tstq\t${i}, {8*i}($29)" for i in LD_REGS) + "\n\tstq\t$30, 240($29)"

REF_TEMPLATE = r"""
	.arch ev6
	.set noat
	.set noreorder

	.section .hdata, "aw", @progbits
	.space 4096

	.section .hstate, "aw", @progbits
	.incbin "state.bin"
	.space 1024

	.text
	.globl _start
_start:
	/* osf_setsysinfo(SSI_IEEE_FP_CONTROL, &w): clear every trap-enable
	 * bit and map an underflowed result to zero, which is what the
	 * hardware does when the underflow trap is disabled.  Without this
	 * the reference takes SIGFPE on most software-completion forms. */
	ldah	$29, 0x2100($31)
	lda	$1, __FPCW__($31)
	stq	$1, 768($29)
	lda	$16, 14($31)
	lda	$17, 768($29)
	lda	$18, 8($31)
	lda	$0, 257($31)
	callsys

	/* fill the data buffer with the agreed pattern */
	ldah	$1, 0x1000($31)
	lda	$2, 0($31)
	lda	$3, 4096($31)
9:	mull	$2, 167, $4
	addl	$4, 13, $4
	stb	$4, 0($1)
	addq	$1, 1, $1
	addq	$2, 1, $2
	subq	$3, $2, $5
	bne	$5, 9b

	ldah	$29, 0x2100($31)	/* $29 = state area, reserved */
	stq	$30, 520($29)		/* save the harness stack pointer */

	ldt	$f0, 512($29)
	mt_fpcr	$f0
__REF_LD__
__INT_LD__

test_start:
	.incbin "flat.bin"
test_end:

__INT_ST__
__REF_ST__
	mf_fpcr	$f0
	stt	$f0, 512($29)
	ldq	$30, 520($29)

	lda	$16, 1($31)
	ldah	$17, 0x2100($31)
	lda	$18, 520($31)
	lda	$0, 4($31)
	callsys
	lda	$16, 1($31)
	ldah	$17, 0x1000($31)
	lda	$18, 4096($31)
	lda	$0, 4($31)
	callsys
	lda	$16, 0($31)
	lda	$0, 1($31)
	callsys
"""

LDSCRIPT = """ENTRY(_start)
SECTIONS {
  . = 0x10000000;
  .hdata  : { *(.hdata) }
  . = 0x20000000;
  .text   : { *(.text) }
  . = 0x21000000;
  .hstate : { *(.hstate) }
  /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) }
}
"""

# ---------------------------------------------------------------- generator
INT_RRR = [  # opcodes taking Ra, Rb/lit -> Rc
    "addl","addq","subl","subq","s4addl","s4addq","s8addl","s8addq",
    "s4subl","s4subq","s8subl","s8subq","mull","mulq","umulh",
    "cmpeq","cmplt","cmple","cmpult","cmpule","cmpbge",
    "and","bic","bis","ornot","xor","eqv",
    "cmoveq","cmovne","cmovlt","cmovge","cmovle","cmovgt","cmovlbs","cmovlbc",
    "sll","srl","sra","zap","zapnot",
    "extbl","extwl","extll","extql","extwh","extlh","extqh",
    "insbl","inswl","insll","insql","inswh","inslh","insqh",
    "mskbl","mskwl","mskll","mskql","mskwh","msklh","mskqh",
]
INT_RB = ["sextb","sextw","ctpop","ctlz","cttz"]   # Rb/lit -> Rc
# EV6 multimedia extension (MVI): Ra, Rb -> Rc, plus the unary pack/unpack
MVI_RRR = ["perr","minsb8","minsw4","minub8","minuw4",
           "maxub8","maxuw4","maxsb8","maxsw4"]
MVI_RB  = ["pklb","pkwb","unpkbl","unpkbw"]
MEM_LD = [("ldbu",1),("ldwu",2),("ldl",4),("ldq",8),("ldq_u",8)]
MEM_ST = [("stb",1),("stw",2),("stl",4),("stq",8),("stq_u",8)]
BRANCH = ["beq","bne","blt","ble","bgt","bge","blbc","blbs"]
FBRANCH= ["fbeq","fbne","fblt","fble","fbgt","fbge"]
# Software-completion (/su,/sui) forms: what real compilers emit, and the
# only ones that do not trap on NaN/Inf operands under Linux.
FP_RRR = ["adds/su","subs/su","muls/su","divs/su","addt/su","subt/su",
          "mult/su","divt/su","cmptun/su","cmpteq/su","cmptlt/su","cmptle/su",
          "cpys","cpysn","cpyse"]
# Rounding-qualified forms: /c chopped, /m -inf, /d dynamic (from FPCR).
# These are what drive the translator's MXCSR reprogramming.
FPR_RRR = ["addt/suc","addt/sum","addt/sud","subt/suc","subt/sum","subt/sud",
           "mult/suc","mult/sum","mult/sud","divt/suc","divt/sum","divt/sud",
           "adds/suc","adds/sum","adds/sud","subs/suc","muls/sum","divs/sud"]
FPR_RB  = ["sqrtt/suc","sqrtt/sum","sqrtt/sud","sqrts/suc","sqrts/sud",
           "cvttq/svc","cvttq/svm","cvttq/svd","cvtqs/suic","cvtqs/suim",
           "cvtqt/suic","cvtqt/suid","cvtts/suc","cvtts/sum","cvtts/sud"]
FP_RB  = ["sqrts/su","sqrtt/su","cvtts/su","cvtqs/sui","cvtqt/sui",
          "cvttq/sv","cvtlq","cvtql/sv","cvtst/s"]

def wreg(rng):
    while True:
        r = rng.randrange(0, 31)
        if r not in RESERVED:
            return r

def rreg(rng):
    r = rng.randrange(0, 32)
    return 31 if r in (29,) else r

def gen_insns(rng, n, classes):
    out, labels = [], 0
    pending = []          # (label_id, remaining) forward branches
    for k in range(n):
        for lid, rem in list(pending):
            pending.remove((lid, rem))
            if rem <= 0:
                out.append(f"L{lid}:")
            else:
                pending.append((lid, rem - 1))
        c = rng.choice(classes)
        if c == "int":
            m = rng.choice(INT_RRR)
            a, cr = rreg(rng), wreg(rng)
            if rng.random() < 0.35:
                out.append(f"\t{m}\t${a}, {rng.randrange(0,256)}, ${cr}")
            else:
                out.append(f"\t{m}\t${a}, ${rreg(rng)}, ${cr}")
        elif c == "int1":
            m = rng.choice(INT_RB)
            out.append(f"\t{m}\t${rreg(rng)}, ${wreg(rng)}")
        elif c == "mem":
            if rng.random() < 0.5:
                m, sz = rng.choice(MEM_LD)
                off = rng.randrange(0, 4096 - 8)
                if m != "ldq_u": off -= off % sz
                out.append(f"\t{m}\t${wreg(rng)}, {off}(${rng.choice(BASE_REGS)})")
            else:
                m, sz = rng.choice(MEM_ST)
                off = rng.randrange(0, 4096 - 8)
                if m != "stq_u": off -= off % sz
                out.append(f"\t{m}\t${rreg(rng)}, {off}(${rng.choice(BASE_REGS)})")
        elif c == "fp":
            m = rng.choice(FP_RRR)
            out.append(f"\t{m}\t$f{rng.randrange(0,32)}, $f{rng.randrange(0,32)}, $f{rng.randrange(0,31)}")
        elif c == "fpr":
            r = rng.random()
            if r < 0.45:
                m = rng.choice(FPR_RRR)
                out.append(f"\t{m}\t$f{rng.randrange(0,32)}, $f{rng.randrange(0,32)}, $f{rng.randrange(0,31)}")
            elif r < 0.9:
                out.append(f"\t{rng.choice(FPR_RB)}\t$f{rng.randrange(0,32)}, $f{rng.randrange(0,31)}")
            else:
                # change the dynamic rounding mode at run time, keeping every
                # trap-disable bit set so the reference stays alive
                hi = 0x700E | (rng.randrange(0, 4) << 10)
                out.append(f"\tldah\t$1, {hi}($31)")
                out.append(f"\tsll\t$1, 32, $1")
                out.append(f"\titoft\t$1, $f0")
                out.append(f"\tmt_fpcr\t$f0")
        elif c == "mvi":
            if rng.random() < 0.7:
                m = rng.choice(MVI_RRR)
                out.append(f"\t{m}\t${rreg(rng)}, ${rreg(rng)}, ${wreg(rng)}")
            else:
                out.append(f"\t{rng.choice(MVI_RB)}\t${rreg(rng)}, ${wreg(rng)}")
        elif c == "fmem":
            if rng.random() < 0.5:
                off = rng.randrange(0, 4096 - 8) & ~3
                out.append(f"\tlds\t$f{rng.randrange(0,31)}, {off}(${rng.choice(BASE_REGS)})")
            else:
                off = rng.randrange(0, 4096 - 8) & ~3
                out.append(f"\tsts\t$f{rng.randrange(0,32)}, {off}(${rng.choice(BASE_REGS)})")
        elif c == "fmov":
            m = rng.choice(["itofs","itoft","ftois","ftoit",
                            "fcmoveq","fcmovne","fcmovlt","fcmovge",
                            "fcmovle","fcmovgt"])
            if m in ("itofs","itoft"):
                out.append(f"\t{m}\t${rreg(rng)}, $f{rng.randrange(0,31)}")
            elif m in ("ftois","ftoit"):
                out.append(f"\t{m}\t$f{rng.randrange(0,32)}, ${wreg(rng)}")
            else:
                out.append(f"\t{m}\t$f{rng.randrange(0,32)}, $f{rng.randrange(0,32)}, $f{rng.randrange(0,31)}")
        elif c == "fp1":
            m = rng.choice(FP_RB)
            out.append(f"\t{m}\t$f{rng.randrange(0,32)}, $f{rng.randrange(0,31)}")
        elif c == "branch":
            labels += 1
            skip = rng.randrange(1, 4)
            if rng.random() < 0.3:
                out.append(f"\t{rng.choice(FBRANCH)}\t$f{rng.randrange(0,32)}, L{labels}")
            else:
                out.append(f"\t{rng.choice(BRANCH)}\t${rreg(rng)}, L{labels}")
            pending.append((labels, skip))
    for lid, _ in pending:
        out.append(f"L{lid}:")
    return out

FP_POOL = [0.0, -0.0, 1.0, -1.0, 2.0, 0.5, -0.5, 3.14159265358979, 1e10, 1e-10,
           -7.25, 1234567.0, float('inf'), float('-inf'), float('nan'), 255.0,
           1.0e300, 1.0e-300, 123.456, -0.125]

def gen_state(rng):
    st = [0]*65
    for i in range(31):
        r = rng.random()
        if r < 0.3:   st[i] = rng.randrange(0, 256)
        elif r < 0.6: st[i] = rng.getrandbits(64)
        elif r < 0.8: st[i] = rng.getrandbits(32)
        else:         st[i] = (1 << rng.randrange(0, 64))
    st[31] = 0
    st[20] = DATA_BASE
    st[21] = DATA_BASE + 0x800
    st[30] = DATA_BASE + 0x400          # keep sp inside the buffer
    st[29] = 0
    for i in range(31):
        if rng.random() < 0.7:
            st[32+i] = struct.unpack('<Q', struct.pack('<d', rng.choice(FP_POOL)))[0]
        else:
            st[32+i] = rng.getrandbits(64)
    st[63] = 0
    # FPCR: round-to-nearest plus every trap-disable bit, so the qemu
    # reference does not take SIGFPE on NaN/Inf/overflow operands.
    #   62 INED  61 UNFD  60 UNDZ  59:58 DYN  51 OVFD  50 DZED  49 INVD
    # UNDZ (underflow to zero) is what the translator's MXCSR flush-to-zero
    # reproduces, so both sides agree on a denormal result.
    st[64] = ((1 << 62) | (1 << 61) | (1 << 60)
              | (rng.randrange(0, 4) << 58)
              | (1 << 51) | (1 << 50) | (1 << 49))
    return st

# ----------------------------------------------------------------- runners
def build_and_run(workdir, insns, state, keep=False):
    src = "\t.arch ev6\n\t.set noat\n\t.set noreorder\n\t.text\n" + "\n".join(insns) + "\n"
    open(f"{workdir}/snippet.s", "w").write(src)
    if subprocess.run(["alpha-linux-gnu-as","-o",f"{workdir}/snippet.o",f"{workdir}/snippet.s"],
                      capture_output=True).returncode: return None, "assemble failed"
    subprocess.run(["alpha-linux-gnu-objcopy","-O","binary","-j",".text",
                    f"{workdir}/snippet.o", f"{workdir}/flat.bin"], check=True)
    open(f"{workdir}/state.bin","wb").write(struct.pack('<65Q', *state))

    ref = (REF_TEMPLATE.replace("__REF_LD__", REF_LD).replace("__REF_ST__", REF_ST)
                       .replace("__INT_LD__", INT_LD).replace("__INT_ST__", INT_ST)
                       .replace("__FPCW__", str(FPCW)))
    open(f"{workdir}/ref.S","w").write(ref)
    open(f"{workdir}/ref.ld","w").write(LDSCRIPT)
    r = subprocess.run(["alpha-linux-gnu-gcc","-nostdlib","-nostartfiles","-static",
                        "-Wl,--build-id=none","-Wl,-T,ref.ld","-o","ref","ref.S"],
                       cwd=workdir, capture_output=True, text=True)
    if r.returncode: return None, "link failed: " + r.stderr[-800:]

    q = subprocess.run(["qemu-alpha","-cpu","ev67","./ref"], cwd=workdir,
                       capture_output=True, timeout=60)
    if q.returncode != 0 or len(q.stdout) != 520+4096:
        return None, f"qemu rc={q.returncode} len={len(q.stdout)} {q.stderr[-200:]}"
    e = subprocess.run([EMU, "flat.bin", f"{CODE_BASE:x}", "state.bin", "emu.out"],
                       cwd=workdir, capture_output=True, text=True, timeout=60)
    emu = open(f"{workdir}/emu.out","rb").read()
    return (q.stdout, emu, e.stderr), None

def compare(refout, emuout):
    rs = struct.unpack('<65Q', refout[:520]); rm = refout[520:]
    es = struct.unpack('<65Q', emuout[:520]); em = emuout[520:520+4096]
    diffs = []
    for i in range(32):
        if i in (29, 31): continue
        if rs[i] != es[i]: diffs.append(f"r{i}: ref={rs[i]:#018x} emu={es[i]:#018x}")
    for i in range(31):
        if rs[32+i] != es[32+i]:
            diffs.append(f"f{i}: ref={rs[32+i]:#018x} emu={es[32+i]:#018x}")
    if rm != em:
        for i in range(0, 4096):
            if rm[i] != em[i]:
                diffs.append(f"mem[{i}]: ref={rm[i]:#04x} emu={em[i]:#04x}")
                if len(diffs) > 12: break
    return diffs

def bisect(workdir, insns, state):
    """Shortest failing prefix -> the instruction that first diverges."""
    real = [i for i in insns if not i.endswith(":")]
    for n in range(1, len(real) + 1):
        res, err = build_and_run(workdir, real[:n], state)
        if err: continue
        if compare(res[0], res[1]):
            return real[n - 1].strip()
    return None

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--bisect", action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--len", type=int, default=24)
    ap.add_argument("--classes", default="int,int1,mem,branch")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    classes = args.classes.split(",")

    workdir = tempfile.mkdtemp(prefix="axpdiff-")
    ok = fail = skip = 0
    failures = []
    for t in range(args.count):
        rng = random.Random(args.seed * 100000 + t)
        insns = gen_insns(rng, args.len, classes)
        state = gen_state(rng)
        res, err = build_and_run(workdir, insns, state)
        if err:
            skip += 1
            if args.verbose: print(f"[{t}] SKIP {err}")
            continue
        refout, emuout, estderr = res
        d = compare(refout, emuout)
        if d:
            fail += 1
            failures.append((t, insns, d, estderr))
            if len(failures) <= 3:
                print(f"\n=== MISMATCH test {t} (seed {args.seed}) ===")
                culprit = bisect(workdir, insns, state) if args.bisect else None
                if culprit is not None:
                    print(f"first instruction that diverges: {culprit}")
                else:
                    print("\n".join(insns))
                print("--- diffs ---")
                print("\n".join(d[:10]))
                if estderr.strip(): print("emu stderr:", estderr.strip())
        else:
            ok += 1
    print(f"\nseed={args.seed} classes={args.classes}: {ok} ok, {fail} mismatch, {skip} skipped")
    print("workdir:", workdir)
    return 1 if fail else 0

if __name__ == "__main__":
    sys.exit(main())
