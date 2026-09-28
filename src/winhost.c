/* winhost - the Wine-hosted AXP64 loader.
 *
 * This is axpwin rebuilt as an x86-64 Windows executable, meant to be run
 * under Wine.  The homogeneous rule is unchanged: everything the guest
 * *executes* is Alpha, translated block by block into a private x86-64 code
 * cache.  The host never runs a single guest byte, so all guest memory is
 * mapped READ/WRITE but NOT executable.  Two boundaries cross the divide:
 *
 *   guest -> host   the PALcode (opcode 0) call gate, exactly as before:
 *                   the guest's thin AXP64 USER32/GDI32/KERNEL32 stubs issue
 *                   it, and here we forward to Wine's real host DLLs.
 *
 *   host  -> guest   a callback (a WndProc, a dialog proc, an enum proc) is
 *                   just a guest Alpha address handed to Wine.  When Wine
 *                   calls it, the non-executable guest page faults; a vectored
 *                   handler catches the fault and runs that Alpha routine
 *                   through the JIT, then resumes Wine with the result.
 *
 * The native frontier therefore sits at the Win32 API for now (USER32/GDI32),
 * and can be pushed down to the NtUser / NtGdi syscall layer DLL by DLL
 * later without changing this structure: it is only a question of which
 * names the dispatch table forwards.
 */
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include "emu.h"
#include "helpers.h"

/* --------------------------------------------------------------- memory */
void *guest_map(uint64_t addr, size_t len, int prot)
{
    (void)prot;                              /* guest memory is never host-X */
    uint64_t a = addr & ~0xFFFULL;
    size_t   l = (size_t)((addr - a) + len + 0xFFF) & ~0xFFFULL;
    void *p = VirtualAlloc((void *)(uintptr_t)a, l,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return NULL;
    if ((uintptr_t)p != (uintptr_t)a) return NULL;   /* must be at the ask */
    return (void *)(uintptr_t)addr;
}

/* ------------------------------------------------------- native bindings */
#define THUNK_BASE   0x7F000000ULL
#define THUNK_STRIDE 8
#define MAX_NATIVE   8192
#define STACK_TOP    0x20000000ULL
#define STACK_SIZE   0x00200000ULL
#define HEAP_BASE    0x30000000ULL
#define HEAP_SIZE    0x08000000ULL
#define RETURN_MAGIC   0x00000010ULL
#define CALLBACK_MAGIC 0x00000018ULL

#define LIMBO_BASE 0x39000000ULL
#define LIMBO_SIZE 0x00100000ULL
#define LIMBO_PTR  (LIMBO_BASE + LIMBO_SIZE/2)

static int ctl_trace = 0, ctl_msgs = 0;   /* -c : trace control + file traffic */


typedef void (*NativeFn)(CPUAlpha *cpu);
static struct { const char *name; NativeFn fn; } natives[MAX_NATIVE];
static int n_natives;
static int trace_calls;
static char guest_cmdline[1024];
static JitCtx  g_jit;
static CPUAlpha *g_cpu;

static uint64_t native_bind(const char *name, NativeFn fn)
{
    int i = n_natives++;
    natives[i].name = name;
    natives[i].fn   = fn;
    uint64_t addr = THUNK_BASE + (uint64_t)i * THUNK_STRIDE;
    *(uint32_t *)(uintptr_t)addr = (uint32_t)i;   /* opcode 0 = call gate */
    *(uint32_t *)(uintptr_t)(addr + 4) = 0;
    return addr;
}

/* Alpha (SysV) calling standard: a0..a5 in r16..r21, then 0(sp),8(sp),... */
static uint64_t A(CPUAlpha *c, int n)
{
    if (n < 6) return c->ireg[16 + n];
    return *(uint64_t *)(uintptr_t)(c->ireg[30] + 8 * (n - 6));
}
static void        R(CPUAlpha *c, uint64_t v) { c->ireg[0] = v; }
static const char *gstr(uint64_t va) { return va ? (const char *)(uintptr_t)va : NULL; }

/* An import with no implementation yet: name it the first time it is called,
 * return 0 and keep going.  That is what lets a real application run deep
 * enough to show which entry points actually matter. */
static int miss_seen[MAX_NATIVE];
static int miss_count;
static void n_missing(CPUAlpha *c)
{
    unsigned idx = (unsigned)c->scratch0;
    if (idx < (unsigned)MAX_NATIVE && !miss_seen[idx]) {
        miss_seen[idx] = 1;
        fprintf(stderr, "[stub] %s\n", natives[idx].name);
        fflush(stderr);
        miss_count++;
    }
    R(c, LIMBO_PTR);
}

/* ---- poor-man's watchpoint -------------------------------------------
 * Guest memory is ordinary host memory, so a guest word can be watched by
 * sampling it at the one place every guest->host transition passes through.
 * That brackets an unexpected write between two native calls, which is
 * enough to name the culprit. */
static uint64_t *g_watch_addr;
static uint64_t  g_watch_val;
static const char *g_watch_last = "(start)";
static int       g_watch_armed;      /* page currently write-protected */

/* Re-protect the watched page.  Guest memory is ordinary host memory, so a
 * store to it can be caught the same way any other write watchpoint works:
 * take the page away, let the fault name the guest block, put it back. */
static void watch_protect(void)
{
    DWORD old;
    if (!g_watch_addr) return;
    if (VirtualProtect((void *)((uintptr_t)g_watch_addr & ~0xFFFULL), 0x1000,
                       PAGE_READONLY, &old))
        g_watch_armed = 1;
}

void helper_native(CPUAlpha *cpu, uint32_t insn)
{
    unsigned idx = insn & 0x03FFFFFF;
    if (g_watch_addr && !g_watch_armed) watch_protect();
    if (g_watch_addr && *g_watch_addr != g_watch_val) {
        fprintf(stderr, "[watch] %#llx changed %#llx -> %#llx between %s and %s"
                        " (block pc %#llx, ra %#llx)\n",
                (unsigned long long)(uintptr_t)g_watch_addr,
                (unsigned long long)g_watch_val,
                (unsigned long long)*g_watch_addr,
                g_watch_last,
                idx < (unsigned)n_natives ? natives[idx].name : "?",
                (unsigned long long)cpu->scratch1,
                (unsigned long long)cpu->ireg[26]);
        fflush(stderr);
        g_watch_val = *g_watch_addr;
    }
    if (idx < (unsigned)n_natives) g_watch_last = natives[idx].name;
    if (idx >= (unsigned)n_natives) {
        fprintf(stderr, "[winhost] unbound native thunk %u\n", idx);
        cpu->exit_code = EXIT_UNIMPL;
        return;
    }
    cpu->scratch0 = idx;
    cpu->ret_pc = cpu->ireg[26];             /* default: return to ra */
    if (trace_calls) {
        fprintf(stderr, "[call] %-28s a0=%#llx a1=%#llx a2=%#llx a3=%#llx\n",
                natives[idx].name,
                (unsigned long long)cpu->ireg[16], (unsigned long long)cpu->ireg[17],
                (unsigned long long)cpu->ireg[18], (unsigned long long)cpu->ireg[19]);
        fflush(stderr);
    }
    if (!natives[idx].fn) { n_missing(cpu); return; }
    natives[idx].fn(cpu);
}

/* ------------------------------------------------- host -> guest callback */
/* ---- containing a guest fault ----------------------------------------
 * A fault inside guest code should not kill the emulator.  On real hardware
 * depends.exe would take the exception itself (it imports _XcptFilter and
 * _CxxFrameHandler); until that is wired through, a faulting guest call is
 * abandoned and reported as failure, which is what the application would see
 * from an analysis that went wrong.  The handler cannot unwind from inside
 * itself, so it resumes the thread at guest_abort, which does the jump. */
static void *g_bail[8];
static int   g_bail_active;
static void  guest_abort(void) { __builtin_longjmp(g_bail, 1); }
static uint64_t g_fault_addr, g_fault_pc;
static int      g_faults;

/* Run a guest Alpha routine to completion and return its v0.  Re-entrant:
 * the full register file is saved and restored, and the guest keeps running
 * on its own (guest) stack, wherever sp currently points. */
static uint64_t guest_call(uint64_t fn, uint64_t a0, uint64_t a1,
                           uint64_t a2, uint64_t a3)
{
    CPUAlpha *c = g_cpu;
    /* Everything the gate machinery keeps in the CPU block has to be saved,
     * not just the registers: helper_native parks the outer block's resume
     * address in ret_pc, and the nested call's own gates would overwrite it.
     * (Wine sends WM_NCCREATE from inside the CreateWindowEx gate, so this
     * nesting happens on the very first window.) */
    uint64_t sr[32], sf[32], spc = c->pc, sfp = c->fpcr, sx = c->exit_code;
    uint64_t srp = c->ret_pc, ss0 = c->scratch0, ss1 = c->scratch1;
    memcpy(sr, c->ireg, sizeof sr);
    memcpy(sf, c->freg, sizeof sf);

    c->ireg[16] = a0; c->ireg[17] = a1; c->ireg[18] = a2; c->ireg[19] = a3;
    c->ireg[27] = fn;                        /* pv, for the gcc prologue */
    c->ireg[26] = CALLBACK_MAGIC;            /* ra: where the final ret lands */
    c->pc = fn;
    c->exit_code = 0;
    uint64_t r;
    void *save_bail[8];
    int save_active = g_bail_active;
    memcpy(save_bail, g_bail, sizeof g_bail);
    if (__builtin_setjmp(g_bail) == 0) {
        g_bail_active = 1;
        jit_run_until(&g_jit, c, CALLBACK_MAGIC, 200000000ULL);
        r = c->ireg[0];
    } else {
        r = 0;                        /* the call faulted: report failure */
    }
    g_bail_active = save_active;
    memcpy(g_bail, save_bail, sizeof g_bail);

    memcpy(c->ireg, sr, sizeof sr);
    memcpy(c->freg, sf, sizeof sf);
    c->pc = spc; c->fpcr = sfp; c->exit_code = sx;
    c->ret_pc = srp; c->scratch0 = ss0; c->scratch1 = ss1;
    return r;
}

/* Is this address inside a region that holds guest Alpha code we can run? */
static int is_guest_code(uint64_t a);



static LONG CALLBACK veh(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *ctx = ep->ContextRecord;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        er->NumberParameters >= 2 &&
        er->ExceptionInformation[0] == 8 /* execute */) {
        uint64_t fn = (uint64_t)ctx->Rip;
        if (is_guest_code(fn)) {
            /* Wine just tried to call a guest routine.  Marshal the x64
             * argument registers into the Alpha ones and run it. */
            uint64_t a0 = ctx->Rcx, a1 = ctx->Rdx, a2 = ctx->R8, a3 = ctx->R9;
            uint64_t ret = *(uint64_t *)(uintptr_t)ctx->Rsp;   /* pushed by call */
            uint64_t v0 = guest_call(fn, a0, a1, a2, a3);
            ctx->Rax = v0;
            ctx->Rsp += 8;
            ctx->Rip = ret;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    /* The write watchpoint: report which guest block stored to the word,
     * then let the store through and re-arm at the next gate crossing. */
    if (g_watch_armed && er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        er->NumberParameters >= 2 && er->ExceptionInformation[0] == 1 /* write */ &&
        ((er->ExceptionInformation[1] ^ (uintptr_t)g_watch_addr) & ~0xFFFULL) == 0) {
        DWORD old;
        if (er->ExceptionInformation[1] == (uintptr_t)g_watch_addr)
            fprintf(stderr, "[watch] STORE to %#llx from guest block %#llx "
                            "(ra %#llx, last import %s)\n",
                    (unsigned long long)er->ExceptionInformation[1],
                    (unsigned long long)(g_cpu ? g_cpu->scratch1 : 0),
                    (unsigned long long)(g_cpu ? g_cpu->ireg[26] : 0),
                    (g_cpu && g_cpu->scratch0 < (uint64_t)n_natives)
                        ? natives[g_cpu->scratch0].name : "(none)");
        VirtualProtect((void *)((uintptr_t)g_watch_addr & ~0xFFFULL), 0x1000,
                       PAGE_READWRITE, &old);
        g_watch_armed = 0;
        fflush(stderr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* A genuine guest fault.  If a guest call is in flight, abandon it. */
    if (g_bail_active) {
        g_fault_addr = (uint64_t)er->ExceptionInformation[1];
        g_fault_pc   = g_cpu ? g_cpu->scratch1 : 0;
        g_faults++;
        fprintf(stderr, "[winhost] guest fault at %#llx (block pc=%#llx) - "
                        "abandoning the call\n",
                (unsigned long long)g_fault_addr, (unsigned long long)g_fault_pc);
        fflush(stderr);
        ctx->Rip = (DWORD64)(uintptr_t)guest_abort;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* a genuine guest fault outside any guarded call: report and die */
    fprintf(stderr,
        "\n[winhost] fault %#lx at %p (guest block pc=%#llx, last import=%s)\n"
        "          a0=%#llx a1=%#llx a2=%#llx sp=%#llx ra=%#llx  icount=%llu\n",
        (unsigned long)er->ExceptionCode, (void *)er->ExceptionInformation[1],
        (unsigned long long)(g_cpu ? g_cpu->scratch1 : 0),
        (g_cpu && g_cpu->scratch0 < (uint64_t)n_natives) ? natives[g_cpu->scratch0].name : "(none)",
        (unsigned long long)(g_cpu ? g_cpu->ireg[16] : 0),
        (unsigned long long)(g_cpu ? g_cpu->ireg[17] : 0),
        (unsigned long long)(g_cpu ? g_cpu->ireg[18] : 0),
        (unsigned long long)(g_cpu ? g_cpu->ireg[30] : 0),
        (unsigned long long)(g_cpu ? g_cpu->ireg[26] : 0),
        (unsigned long long)(g_cpu ? g_cpu->icount : 0));
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ============================ the host DLLs ============================= *
 * Everything below native_bind()s into the guest's import table.  The
 * msvcrt/kernel primitives keep the __sys_* shape the existing AXP64
 * KERNEL32/MSVCRT already import; the USER32/GDI32 gates forward straight
 * to Wine, relying on identity mapping so guest pointers are valid host
 * pointers with no copying. */

/* ---- unixlib bottom (kept from axpwin, now on the mingw CRT) ---------- */
static uint64_t heap_cursor = HEAP_BASE;
static void n_sys_write(CPUAlpha *c)
{ R(c, (uint64_t)_write((int)A(c,0), (void *)(uintptr_t)A(c,1), (unsigned)A(c,2))); }
static void n_sys_read(CPUAlpha *c)
{ R(c, (uint64_t)_read((int)A(c,0), (void *)(uintptr_t)A(c,1), (unsigned)A(c,2))); }
static void n_sys_open(CPUAlpha *c)
{ R(c, (uint64_t)(int64_t)_open(gstr(A(c,0)), A(c,1)?_O_RDWR:_O_RDONLY)); }
static void n_sys_close(CPUAlpha *c){ R(c, (uint64_t)_close((int)A(c,0))); }
static void n_sys_seek(CPUAlpha *c)
{ R(c, (uint64_t)_lseek((int)A(c,0),(long)(int64_t)A(c,1),(int)A(c,2))); }
static void n_sys_fsize(CPUAlpha *c)
{ struct _stat st; R(c, _fstat((int)A(c,0),&st)?(uint64_t)-1:(uint64_t)st.st_size); }
static void n_sys_mem(CPUAlpha *c)
{
    uint64_t n=(A(c,0)+0xFFF)&~0xFFFULL, p=heap_cursor;
    if (p+n>HEAP_BASE+HEAP_SIZE){R(c,0);return;}
    heap_cursor+=n; memset((void*)(uintptr_t)p,0,n); R(c,p);
}
static void n_sys_ticks(CPUAlpha *c){ R(c,(uint64_t)GetTickCount()); }
static void n_sys_time(CPUAlpha *c){ R(c,(uint64_t)time(NULL)); }
static void n_sys_exit(CPUAlpha *c)
{ printf("[winhost] guest exit(%lld)\n",(long long)A(c,0)); c->ireg[26]=RETURN_MAGIC; }
static void n_sys_debug(CPUAlpha *c){ const char*s=gstr(A(c,0)); if(s){fputs(s,stdout);fflush(stdout);} }
static void n_sys_cmdline(CPUAlpha *c)
{
    char*b=(char*)(uintptr_t)A(c,0); uint64_t n=A(c,1);
    if(!b||!n){R(c,0);return;} snprintf(b,(size_t)n,"%s",guest_cmdline); R(c,strlen(b));
}

/* MFC42 stub tracing: the generated stub for ordinal N calls this with N and
 * its first four arguments, so the real startup call sequence can be read off
 * without guessing which ordinals matter. */
static int mfc_trace_on = 1, mfc_calls;

/* "Limbo": a zeroed region an unimplemented entry point can return instead of
 * NULL.  Most MFC functions hand back a pointer (a CString's characters, a
 * CWnd, a CDocument), and the caller usually dereferences it immediately —
 * often at a small negative offset, as CString::GetLength does.  Pointing
 * into the middle of a large zeroed block turns what would be an immediate
 * crash into a benign read of 0, which lets a real application run far
 * enough to show what it needs next. */
static void n_mfc_trace(CPUAlpha *c)
{
    if (mfc_trace_on && mfc_calls < 4000) {
        mfc_calls++;
        fprintf(stderr, "[mfc] #%-5llu a0=%#llx a1=%#llx a2=%#llx a3=%#llx a4=%#llx"
                        " a5=%#llx a6=%#llx a7=%#llx\n",
                (unsigned long long)A(c,0), (unsigned long long)A(c,1),
                (unsigned long long)A(c,2), (unsigned long long)A(c,3),
                (unsigned long long)A(c,4), (unsigned long long)A(c,5),
                (unsigned long long)A(c,6), (unsigned long long)A(c,7),
                (unsigned long long)A(c,8));
        fflush(stderr);
    }
    R(c, LIMBO_PTR);
}

/* wsprintfA: the Alpha calling standard puts a0..a5 in registers and the
 * rest on the stack, and A() already knows both, so the variadic tail can be
 * walked directly.  depends.exe builds every message with this, including
 * the red "Error opening file. File not found (2)." lines. */
static void gu_wsprintfA(CPUAlpha *c)
{
    char *out = (char *)(uintptr_t)A(c, 0);
    const char *f = gstr(A(c, 1));
    if (!out || !f) { R(c, 0); return; }
    char *o = out; int ai = 2;
    while (*f) {
        if (*f != '%') { *o++ = *f++; continue; }
        char spec[48]; int k = 0; spec[k++] = *f++;
        int wide = 0;
        while (*f && k < 40 && !strchr("diouxXcspeEfgG%", *f)) {
            if (*f == 'l' || *f == 'I') wide = 1;
            if (*f == 'I' && f[1] == '6' && f[2] == '4') { f += 2; continue; }
            spec[k++] = *f++;
        }
        if (!*f) break;
        char conv = *f++;
        switch (conv) {
        case '%': *o++ = '%'; break;
        case 's': {
            spec[k++] = 's'; spec[k] = 0;
            const char *v = gstr(A(c, ai++));
            o += sprintf(o, spec, v ? v : "(null)");
            break;
        }
        case 'c':
            spec[k++] = 'c'; spec[k] = 0;
            o += sprintf(o, spec, (int)A(c, ai++));
            break;
        case 'p':
            o += sprintf(o, "%08llX", (unsigned long long)A(c, ai++));
            break;
        default:
            if (wide) { spec[k++] = 'l'; spec[k++] = 'l'; }
            spec[k++] = conv; spec[k] = 0;
            if (wide) o += sprintf(o, spec, (long long)A(c, ai++));
            else      o += sprintf(o, spec, (int)A(c, ai++));
            break;
        }
    }
    *o = 0;
    R(c, (uint64_t)(unsigned)(o - out));
}

/* __mfc_watch(addr): start sampling a guest quadword at every gate crossing */
static void n_mfc_watch(CPUAlpha *c)
{
    g_watch_addr = (uint64_t *)(uintptr_t)A(c, 0);
    g_watch_val  = g_watch_addr ? *g_watch_addr : 0;
    fprintf(stderr, "[watch] arm %#llx = %#llx\n",
            (unsigned long long)(uintptr_t)g_watch_addr,
            (unsigned long long)g_watch_val);
    watch_protect();
    fflush(stderr);
    R(c, 0);
}

/* ---- _Ots* compiler helpers -------------------------------------------
 * Microsoft's Alpha compiler calls these for string and block operations and
 * assumes they preserve every register it did not pass an argument in.
 * depends.exe:0x40f220 shows the assumption directly:
 *
 *      mov  a0,t0            ; keep the string in t0
 *      bsr  ra,_Otsstrlen
 *      addq t0,v0,a0         ; t0 still live afterwards
 *
 * A C implementation compiled by gcc is free to clobber t0, so these cannot
 * live in the AXP64 MSVCRT: implemented here as native gates, only v0 is
 * written and every other guest register is untouched by construction.
 * This is the same reason __divq and friends are native.
 */
static void n_Otsstrlen(CPUAlpha *c)
{ const char *s = gstr(A(c,0)); R(c, s ? (uint64_t)strlen(s) : 0); }
static void n_Otsstrcpy(CPUAlpha *c)
{
    char *d = (char *)(uintptr_t)A(c,0); const char *s = gstr(A(c,1));
    if (d && s) strcpy(d, s);
    R(c, A(c,0));
}
static void n_Otsstrcmp(CPUAlpha *c)
{
    const char *a = gstr(A(c,0)), *b = gstr(A(c,1));
    R(c, (uint64_t)(int64_t)strcmp(a ? a : "", b ? b : ""));
}
static void n_OtsZero(CPUAlpha *c)
{
    void *d = (void *)(uintptr_t)A(c,0);
    if (d) memset(d, 0, (size_t)A(c,1));
    R(c, A(c,0));
}
static void n_OtsFill(CPUAlpha *c)
{
    void *d = (void *)(uintptr_t)A(c,0);
    if (d) memset(d, (int)A(c,2), (size_t)A(c,1));
    R(c, A(c,0));
}
static void n_OtsMove(CPUAlpha *c)
{
    void *d = (void *)(uintptr_t)A(c,0); const void *s = (const void *)(uintptr_t)A(c,1);
    if (d && s) memmove(d, s, (size_t)A(c,2));
    R(c, A(c,0));
}

/* A guest call made through the host so it runs inside the fault guard.
 * MFC uses it for the document's own analysis: a fault there is contained
 * and reported as failure instead of taking the process down, which is what
 * the application's own SEH would do on real hardware. */
static void n_guarded_call(CPUAlpha *c)
{
    uint64_t fn = A(c,0), a0 = A(c,1), a1 = A(c,2), a2 = A(c,3);
    if (!fn) { R(c, 0); return; }
    int before = g_faults;
    uint64_t r = guest_call(fn, a0, a1, a2, 0);
    if (g_faults != before)
        fprintf(stderr, "[winhost] guarded call faulted; reported as failure\n");
    R(c, r);
}

/* division helpers (t10/t11 -> t12, return via t9) */
#define DIVHELPER(NAME,EXPR) static void NAME(CPUAlpha*c){ \
    uint64_t a=c->ireg[24],b=c->ireg[25]; c->ireg[27]=(EXPR); c->ret_pc=c->ireg[23]; }
DIVHELPER(n_divl,  b?(uint64_t)(int64_t)(int32_t)((int32_t)a/(int32_t)b):0)
DIVHELPER(n_divlu, b?(uint64_t)(int64_t)(int32_t)((uint32_t)a/(uint32_t)b):0)
DIVHELPER(n_reml,  b?(uint64_t)(int64_t)(int32_t)((int32_t)a%(int32_t)b):0)
DIVHELPER(n_remlu, b?(uint64_t)(int64_t)(int32_t)((uint32_t)a%(uint32_t)b):0)
DIVHELPER(n_divq,  b?(uint64_t)((int64_t)a/(int64_t)b):0)
DIVHELPER(n_divqu, b?a/b:0)
DIVHELPER(n_remq,  b?(uint64_t)((int64_t)a%(int64_t)b):0)
DIVHELPER(n_remqu, b?a%b:0)

/* ---- USER32 / GDI32 forwarding to Wine --------------------------------- *
 * Handles and ints pass by value; pointers (strings, RECT*, PAINTSTRUCT*,
 * MSG*, WNDCLASS*) are guest addresses == host addresses, so Wine reads and
 * writes them in place.  A WNDCLASS.lpfnWndProc is a guest Alpha address:
 * Wine stores it, and calling it later trips the veh() callback path. */
#define FWD0(N,F,RT) static void N(CPUAlpha*c){ R(c,(uint64_t)(RT)F()); }
#define G(c,n) A(c,n)
static void gu_RegisterClassA(CPUAlpha*c){ R(c,(uint64_t)RegisterClassA((const WNDCLASSA*)(uintptr_t)A(c,0))); }
static void gu_RegisterClassExA(CPUAlpha*c){ R(c,(uint64_t)RegisterClassExA((const WNDCLASSEXA*)(uintptr_t)A(c,0))); }
/* CreateWindowExA has 12 args: the guest stub packs them into a struct. */
typedef struct { uint64_t ex; uint64_t cls; uint64_t name; uint64_t style;
    int32_t x,y,w,h; uint64_t parent,menu,inst,param; } CWArgs;
static void gu_CreateWindowExA(CPUAlpha*c){
    CWArgs*p=(CWArgs*)(uintptr_t)A(c,0);
    HWND h=CreateWindowExA((DWORD)p->ex,(LPCSTR)(uintptr_t)p->cls,(LPCSTR)(uintptr_t)p->name,
        (DWORD)p->style,p->x,p->y,p->w,p->h,(HWND)(uintptr_t)p->parent,
        (HMENU)(uintptr_t)p->menu,(HINSTANCE)(uintptr_t)p->inst,(LPVOID)(uintptr_t)p->param);
    R(c,(uint64_t)(uintptr_t)h);
}
static void gu_ShowWindow(CPUAlpha*c){ R(c,(uint64_t)ShowWindow((HWND)(uintptr_t)A(c,0),(int)A(c,1))); }
static void gu_UpdateWindow(CPUAlpha*c){ R(c,(uint64_t)UpdateWindow((HWND)(uintptr_t)A(c,0))); }
static void gu_DestroyWindow(CPUAlpha*c){ R(c,(uint64_t)DestroyWindow((HWND)(uintptr_t)A(c,0))); }
static void gu_DefWindowProcA(CPUAlpha*c){ R(c,(uint64_t)DefWindowProcA((HWND)(uintptr_t)A(c,0),(UINT)A(c,1),(WPARAM)A(c,2),(LPARAM)A(c,3))); }
static void gu_GetMessageA(CPUAlpha*c){ R(c,(uint64_t)(int64_t)GetMessageA((MSG*)(uintptr_t)A(c,0),(HWND)(uintptr_t)A(c,1),(UINT)A(c,2),(UINT)A(c,3))); }
static void gu_PeekMessageA(CPUAlpha*c){ R(c,(uint64_t)PeekMessageA((MSG*)(uintptr_t)A(c,0),(HWND)(uintptr_t)A(c,1),(UINT)A(c,2),(UINT)A(c,3),(UINT)A(c,4))); }
static void gu_TranslateMessage(CPUAlpha*c){ R(c,(uint64_t)TranslateMessage((const MSG*)(uintptr_t)A(c,0))); }
static void gu_DispatchMessageA(CPUAlpha*c){ R(c,(uint64_t)DispatchMessageA((const MSG*)(uintptr_t)A(c,0))); }
static void gu_PostQuitMessage(CPUAlpha*c){ PostQuitMessage((int)A(c,0)); }
static void gu_PostMessageA(CPUAlpha*c){ R(c,(uint64_t)PostMessageA((HWND)(uintptr_t)A(c,0),(UINT)A(c,1),(WPARAM)A(c,2),(LPARAM)A(c,3))); }

static void gu_SendMessageA(CPUAlpha*c){
    UINT m=(UINT)A(c,1);
    LRESULT r=SendMessageA((HWND)(uintptr_t)A(c,0),m,(WPARAM)A(c,2),(LPARAM)A(c,3));
    /* control traffic: LVM_ 0x1000.., TVM_ 0x1100.., HDM_ 0x1200.. */
    if (ctl_trace && m>=0x1000 && m<0x1300 && ctl_msgs<400) {
        ctl_msgs++;
        fprintf(stderr,"[ctl] hwnd=%#llx msg=%#x wp=%#llx lp=%#llx -> %lld\n",
            (unsigned long long)A(c,0),m,(unsigned long long)A(c,2),
            (unsigned long long)A(c,3),(long long)r);
        fflush(stderr);
    }
    R(c,(uint64_t)r);
}
static void gu_BeginPaint(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)BeginPaint((HWND)(uintptr_t)A(c,0),(PAINTSTRUCT*)(uintptr_t)A(c,1))); }
static void gu_EndPaint(CPUAlpha*c){ R(c,(uint64_t)EndPaint((HWND)(uintptr_t)A(c,0),(const PAINTSTRUCT*)(uintptr_t)A(c,1))); }
static void gu_GetClientRect(CPUAlpha*c){ R(c,(uint64_t)GetClientRect((HWND)(uintptr_t)A(c,0),(RECT*)(uintptr_t)A(c,1))); }
static void gu_InvalidateRect(CPUAlpha*c){ R(c,(uint64_t)InvalidateRect((HWND)(uintptr_t)A(c,0),(const RECT*)(uintptr_t)A(c,1),(BOOL)A(c,2))); }
static void gu_FillRect(CPUAlpha*c){ R(c,(uint64_t)FillRect((HDC)(uintptr_t)A(c,0),(const RECT*)(uintptr_t)A(c,1),(HBRUSH)(uintptr_t)A(c,2))); }
static void gu_LoadCursorA(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)LoadCursorA((HINSTANCE)(uintptr_t)A(c,0),(LPCSTR)(uintptr_t)A(c,1))); }
static void gu_LoadIconA(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)LoadIconA((HINSTANCE)(uintptr_t)A(c,0),(LPCSTR)(uintptr_t)A(c,1))); }
static void gu_SetTimer(CPUAlpha*c){ R(c,(uint64_t)SetTimer((HWND)(uintptr_t)A(c,0),(UINT_PTR)A(c,1),(UINT)A(c,2),(TIMERPROC)(uintptr_t)A(c,3))); }
static void gu_KillTimer(CPUAlpha*c){ R(c,(uint64_t)KillTimer((HWND)(uintptr_t)A(c,0),(UINT_PTR)A(c,1))); }
static void gu_GetSystemMetrics(CPUAlpha*c){ R(c,(uint64_t)(int64_t)GetSystemMetrics((int)A(c,0))); }
static void gu_MessageBoxA(CPUAlpha*c){ R(c,(uint64_t)(int64_t)MessageBoxA((HWND)(uintptr_t)A(c,0),(LPCSTR)(uintptr_t)A(c,1),(LPCSTR)(uintptr_t)A(c,2),(UINT)A(c,3))); }
static void gu_SetWindowTextA(CPUAlpha*c){ R(c,(uint64_t)SetWindowTextA((HWND)(uintptr_t)A(c,0),(LPCSTR)(uintptr_t)A(c,1))); }
static void gu_MoveWindow(CPUAlpha*c){ R(c,(uint64_t)MoveWindow((HWND)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(int)A(c,3),(int)A(c,4),(BOOL)A(c,5))); }

static void gd_CreateSolidBrush(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)CreateSolidBrush((COLORREF)A(c,0))); }
static void gd_DeleteObject(CPUAlpha*c){ R(c,(uint64_t)DeleteObject((HGDIOBJ)(uintptr_t)A(c,0))); }
static void gd_SetBkMode(CPUAlpha*c){ R(c,(uint64_t)(int64_t)SetBkMode((HDC)(uintptr_t)A(c,0),(int)A(c,1))); }
static void gd_SetTextColor(CPUAlpha*c){ R(c,(uint64_t)SetTextColor((HDC)(uintptr_t)A(c,0),(COLORREF)A(c,1))); }
static void gd_SetBkColor(CPUAlpha*c){ R(c,(uint64_t)SetBkColor((HDC)(uintptr_t)A(c,0),(COLORREF)A(c,1))); }
static void gd_TextOutA(CPUAlpha*c){ R(c,(uint64_t)TextOutA((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(LPCSTR)(uintptr_t)A(c,3),(int)A(c,4))); }
static void gd_Ellipse(CPUAlpha*c){ R(c,(uint64_t)Ellipse((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(int)A(c,3),(int)A(c,4))); }
static void gd_Rectangle(CPUAlpha*c){ R(c,(uint64_t)Rectangle((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(int)A(c,3),(int)A(c,4))); }
static void gd_MoveToEx(CPUAlpha*c){ R(c,(uint64_t)MoveToEx((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(POINT*)(uintptr_t)A(c,3))); }
static void gd_LineTo(CPUAlpha*c){ R(c,(uint64_t)LineTo((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2))); }
static void gd_SelectObject(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)SelectObject((HDC)(uintptr_t)A(c,0),(HGDIOBJ)(uintptr_t)A(c,1))); }
static void gd_CreatePen(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)CreatePen((int)A(c,0),(int)A(c,1),(COLORREF)A(c,2))); }
static void gd_GetStockObject(CPUAlpha*c){ R(c,(uint64_t)(uintptr_t)GetStockObject((int)A(c,0))); }
static void gd_SetPixel(CPUAlpha*c){ R(c,(uint64_t)SetPixel((HDC)(uintptr_t)A(c,0),(int)A(c,1),(int)A(c,2),(COLORREF)A(c,3))); }

/* ------------------------------------------------------------ PE image */
typedef struct {
    uint64_t base, size, entry;
    const char *path; char name[64];
    uint8_t *file; size_t fsize;
    uint32_t dir_rva[16], dir_size[16];
} Module;
#define RD16(p) (*(uint16_t*)(p))
#define RD32(p) (*(uint32_t*)(p))
#define RD64(p) (*(uint64_t*)(p))
static Module mods[24]; static int nmods;
static int keep_going, nmissing;
static uint64_t pe_export(Module*m,const char*name);
static uint64_t pe_export_ord(Module*m,uint64_t ord);
static int pe_load(Module*m,const char*path,int verbose);
static int pe_bind_imports(Module*m,int verbose);

static int is_guest_code(uint64_t a)
{
    for (int i=0;i<nmods;i++)
        if (a>=mods[i].base && a<mods[i].base+mods[i].size) return 1;
    return 0;                                 /* thunks live in THUNK_BASE, not code */
}

static Module *find_module(const char*name){
    if(!name||!*name) return &mods[0];
    for(int i=0;i<nmods;i++) if(!_stricmp(mods[i].name,name)) return &mods[i];
    for(int i=0;i<nmods;i++){ const char*a=mods[i].name,*b=name;
        size_t la=strcspn(a,"."),lb=strcspn(b,".");
        if(la==lb&&!_strnicmp(a,b,la)) return &mods[i]; }
    return NULL;
}
static Module *module_by_base(uint64_t b){
    if(!b) return &mods[0];
    for(int i=0;i<nmods;i++) if(mods[i].base==b) return &mods[i];
    return NULL;
}
static void n_sys_load(CPUAlpha*c){
    const char*path=gstr(A(c,0)); Module*m=path?find_module(path):NULL;
    if(m){R(c,m->base);return;}
    if(nmods>=24||!path){R(c,0);return;}
    if(pe_load(&mods[nmods],_strdup(path),0)!=0){R(c,0);return;}
    nmods++; if(pe_bind_imports(&mods[nmods-1],0)!=0){R(c,0);return;}
    R(c,mods[nmods-1].base);
}
static void n_sys_module_base(CPUAlpha*c){ Module*m=find_module(A(c,0)?gstr(A(c,0)):NULL); R(c,m?m->base:0); }
static void n_sys_module_path(CPUAlpha*c){
    Module*m=module_by_base(A(c,0)); char*b=(char*)(uintptr_t)A(c,1); uint64_t n=A(c,2);
    if(!m||!b||!n){R(c,0);return;} char t[512]; snprintf(t,sizeof t,"C:\\%s",m->name);
    snprintf(b,(size_t)n,"%s",t); R(c,strlen(b));
}
static void n_sys_module_proc(CPUAlpha*c){
    Module*m=module_by_base(A(c,0)); if(!m){R(c,0);return;}
    R(c, A(c,1)?pe_export(m,gstr(A(c,1))):pe_export_ord(m,A(c,2)));
}

/* generated ADVAPI32/SHELL32/COMDLG32/COMCTL32 gates (need A()/R() above) */
#include "fwd_gen.h"

/* Same two entry points, but naming the path they were given.  Listed before
 * the generated table so they win the lookup; this is how the application's
 * module search is followed. */
static void g_file_CreateFileA(CPUAlpha *c)
{
    const char *p = gstr(A(c,0));
    HANDLE h = CreateFileA(p, (DWORD)A(c,1), (DWORD)A(c,2), NULL,
                           (DWORD)A(c,4), (DWORD)A(c,5), NULL);
    if (ctl_trace) { fprintf(stderr, "[file] CreateFileA(\"%s\") -> %s\n",
                             p ? p : "(null)",
                             h == INVALID_HANDLE_VALUE ? "FAILED" : "ok"); fflush(stderr); }
    R(c, (uint64_t)(uintptr_t)h);
}
static void g_file_FindFirstFileA(CPUAlpha *c)
{
    const char *p = gstr(A(c,0));
    HANDLE h = FindFirstFileA(p, (WIN32_FIND_DATAA *)(uintptr_t)A(c,1));
    if (ctl_trace) { fprintf(stderr, "[file] FindFirstFileA(\"%s\") -> %s\n",
                             p ? p : "(null)",
                             h == INVALID_HANDLE_VALUE ? "not found" : "found"); fflush(stderr); }
    R(c, (uint64_t)(uintptr_t)h);
}

/* ---- resources out of the guest image ---------------------------------
 * FindResource and friends work on OUR guest modules, which Wine knows
 * nothing about, so they cannot be forwarded: the .rsrc tree is walked here.
 * The layout is the standard three levels, type -> name -> language, each a
 * IMAGE_RESOURCE_DIRECTORY followed by named then id entries. */
static uint8_t *res_find(Module *m, uint32_t type, uint32_t name, uint32_t *size)
{
    uint32_t rva = m->dir_rva[2];
    if (!rva) return NULL;
    uint8_t *root = (uint8_t *)(uintptr_t)(m->base + rva);
    uint8_t *lvl = root;
    uint32_t want[2] = { type, name };
    for (int depth = 0; depth < 3; depth++) {
        uint16_t nnamed = RD16(lvl + 12), nid = RD16(lvl + 14);
        uint8_t *ent = lvl + 16;
        uint8_t *next = NULL;
        for (int i = 0; i < nnamed + nid; i++, ent += 8) {
            uint32_t id = RD32(ent), off = RD32(ent + 4);
            if (depth < 2) {
                if (id & 0x80000000u) continue;      /* named: not used here */
                if (id != want[depth]) continue;
            }
            next = root + (off & 0x7FFFFFFF);
            if (!(off & 0x80000000u)) {              /* a leaf */
                if (size) *size = RD32(next + 4);
                return (uint8_t *)(uintptr_t)(m->base + RD32(next));
            }
            break;
        }
        if (!next) return NULL;
        lvl = next;
    }
    return NULL;
}

/* USER32!LoadMenuA over a guest module: pull the MENU template out of the
 * guest image and hand the bytes to Wine, which builds a real HMENU. */
static void gu_LoadMenuFromModule(CPUAlpha *c)
{
    Module *m = module_by_base(A(c,0));
    uint32_t sz = 0;
    uint8_t *r = m ? res_find(m, 4 /* RT_MENU */, (uint32_t)A(c,1), &sz) : NULL;
    if (!r) { R(c, 0); return; }
    HMENU h = LoadMenuIndirectA(r);
    R(c, (uint64_t)(uintptr_t)h);
}

/* CImageList::Create(nBitmapID, cx, nGrow, crMask) over a guest module.
 * depends.exe builds its four image lists from its own RT_BITMAP resources
 * (the strips of module and error icons).  A resource bitmap is a DIB with
 * no file header, so it goes straight to CreateDIBitmap, and Wine's own
 * comctl32 then owns the image list the controls will draw from. */
static void gu_ImageListFromBitmap(CPUAlpha *c)
{
    Module  *m  = module_by_base(A(c,0));
    uint32_t id = (uint32_t)A(c,1);
    int      cx = (int)A(c,2);
    COLORREF mask = (COLORREF)A(c,3);
    uint32_t sz = 0;
    uint8_t *r = m ? res_find(m, 2 /* RT_BITMAP */, id, &sz) : NULL;
    if (!r) { fprintf(stderr, "[winhost] bitmap %u not found\n", id); R(c, 0); return; }

    BITMAPINFOHEADER *bih = (BITMAPINFOHEADER *)r;
    int ncol = bih->biClrUsed ? (int)bih->biClrUsed
             : (bih->biBitCount <= 8 ? 1 << bih->biBitCount : 0);
    void *bits = r + bih->biSize + (size_t)ncol * sizeof(RGBQUAD);
    int w = (int)bih->biWidth, h = (int)(bih->biHeight < 0 ? -bih->biHeight : bih->biHeight);

    HDC dc = GetDC(NULL);
    HBITMAP hb = CreateDIBitmap(dc, bih, CBM_INIT, bits, (BITMAPINFO *)bih, DIB_RGB_COLORS);
    ReleaseDC(NULL, dc);
    if (!hb) { fprintf(stderr, "[winhost] bitmap %u: CreateDIBitmap failed\n", id); R(c, 0); return; }

    if (cx <= 0) cx = h;
    HIMAGELIST il = ImageList_Create(cx, h, ILC_COLOR24 | ILC_MASK, w / (cx ? cx : 1), 4);
    int idx = il ? ImageList_AddMasked(il, hb, mask) : -1;
    DeleteObject(hb);
    fprintf(stderr, "[winhost] imagelist id=%u %dx%d strip=%dx%d -> %p (first=%d)\n",
            id, cx, h, w, h, (void *)il, idx);
    fflush(stderr);
    R(c, (uint64_t)(uintptr_t)il);
}

/* CToolBar::LoadToolBar over a guest module.  An RT_TOOLBAR resource is a
 * four-WORD header (version, button width, button height, item count)
 * followed by one command id per item, zero meaning a separator; the button
 * images are the RT_BITMAP of the same id.  Wine's own comctl32 then owns a
 * real ToolbarWindow32, exactly as it would on the hardware. */
static void gu_ToolbarFromModule(CPUAlpha *c)
{
    Module  *m      = module_by_base(A(c,0));
    uint32_t id     = (uint32_t)A(c,1);
    HWND     parent = (HWND)(uintptr_t)A(c,2);
    uint32_t ctlid  = (uint32_t)A(c,3);
    int     *pheight= (int *)(uintptr_t)A(c,4);
    uint32_t sz = 0;
    uint8_t *tb = m ? res_find(m, 241 /* RT_TOOLBAR */, id, &sz) : NULL;
    if (!tb || !parent) { fprintf(stderr, "[winhost] toolbar %u not found\n", id);
                          R(c, 0); return; }
    unsigned cx = RD16(tb + 2), cy = RD16(tb + 4), n = RD16(tb + 6);
    if (!n || n > 256) { R(c, 0); return; }

    HWND h = CreateWindowExA(0, TOOLBARCLASSNAME, NULL,
                             WS_CHILD | WS_VISIBLE | CCS_TOP | TBSTYLE_FLAT |
                             TBSTYLE_TOOLTIPS,
                             0, 0, 0, 0, parent, (HMENU)(uintptr_t)ctlid,
                             (HINSTANCE)(uintptr_t)A(c,0), NULL);
    if (!h) { R(c, 0); return; }
    SendMessageA(h, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessageA(h, TB_SETBITMAPSIZE, 0, MAKELONG(cx, cy));

    uint32_t bsz = 0;
    uint8_t *bm = res_find(m, 2 /* RT_BITMAP */, id, &bsz);
    int nimg = 0;
    for (unsigned i = 0; i < n; i++) if (RD16(tb + 8 + 2 * i)) nimg++;
    if (bm) {
        BITMAPINFOHEADER *bih = (BITMAPINFOHEADER *)bm;
        int ncol = bih->biClrUsed ? (int)bih->biClrUsed
                 : (bih->biBitCount <= 8 ? 1 << bih->biBitCount : 0);
        void *bits = bm + bih->biSize + (size_t)ncol * sizeof(RGBQUAD);
        HDC dc = GetDC(NULL);
        HBITMAP hb = CreateDIBitmap(dc, bih, CBM_INIT, bits, (BITMAPINFO *)bih,
                                    DIB_RGB_COLORS);
        ReleaseDC(NULL, dc);
        if (hb) {
            TBADDBITMAP ab; ab.hInst = NULL; ab.nID = (UINT_PTR)hb;
            SendMessageA(h, TB_ADDBITMAP, nimg, (LPARAM)&ab);
        }
    }
    TBBUTTON *btn = calloc(n, sizeof *btn);
    int img = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned cmd = RD16(tb + 8 + 2 * i);
        if (!cmd) { btn[i].fsStyle = TBSTYLE_SEP; btn[i].iBitmap = 6; }
        else { btn[i].iBitmap = img++; btn[i].idCommand = (int)cmd;
               btn[i].fsState = TBSTATE_ENABLED; btn[i].fsStyle = TBSTYLE_BUTTON; }
    }
    SendMessageA(h, TB_ADDBUTTONS, n, (LPARAM)btn);
    free(btn);
    SendMessageA(h, TB_AUTOSIZE, 0, 0);
    RECT rc; GetWindowRect(h, &rc);
    if (pheight) *pheight = rc.bottom - rc.top;
    fprintf(stderr, "[winhost] toolbar id=%u %ux%u, %u items (%d images) -> %p h=%d\n",
            id, cx, cy, n, nimg, (void *)h, pheight ? *pheight : 0);
    fflush(stderr);
    R(c, (uint64_t)(uintptr_t)h);
}

/* The string table: strings are stored in blocks of 16, each a WORD length
 * followed by that many UTF-16 characters.  Block id = (id / 16) + 1. */
static void gu_LoadStringFromModule(CPUAlpha *c)
{
    Module *m = module_by_base(A(c,0));
    uint32_t id = (uint32_t)A(c,1);
    char *buf = (char *)(uintptr_t)A(c,2);
    uint32_t cap = (uint32_t)A(c,3);
    if (!m || !buf || !cap) { R(c, 0); return; }
    uint32_t sz = 0;
    uint8_t *r = res_find(m, 6 /* RT_STRING */, id / 16 + 1, &sz);
    if (!r) { buf[0] = 0; R(c, 0); return; }
    uint8_t *p = r;
    for (uint32_t i = 0; i < 16; i++) {
        uint16_t len = RD16(p); p += 2;
        if (i == (id & 15)) {
            uint32_t n = len < cap - 1 ? len : cap - 1;
            for (uint32_t k = 0; k < n; k++) buf[k] = (char)RD16(p + 2 * k);
            buf[n] = 0;
            R(c, n);
            return;
        }
        p += 2 * len;
    }
    buf[0] = 0; R(c, 0);
}
static void gu_SetMenu(CPUAlpha *c)
{ R(c, (uint64_t)SetMenu((HWND)(uintptr_t)A(c,0), (HMENU)(uintptr_t)A(c,1))); }

static const struct { const char*name; NativeFn fn; } builtin[] = {
    {"__divl",n_divl},{"__divlu",n_divlu},{"__reml",n_reml},{"__remlu",n_remlu},
    {"__divq",n_divq},{"__divqu",n_divqu},{"__remq",n_remq},{"__remqu",n_remqu},
    {"__sys_write",n_sys_write},{"__sys_read",n_sys_read},{"__sys_open",n_sys_open},
    {"__sys_close",n_sys_close},{"__sys_seek",n_sys_seek},{"__sys_fsize",n_sys_fsize},
    {"__sys_mem",n_sys_mem},{"__sys_ticks",n_sys_ticks},{"__sys_time",n_sys_time},
    {"__sys_exit",n_sys_exit},{"__sys_debug",n_sys_debug},{"__sys_cmdline",n_sys_cmdline},
    {"__sys_load",n_sys_load},{"__sys_module_base",n_sys_module_base},
    {"__sys_module_path",n_sys_module_path},{"__sys_module_proc",n_sys_module_proc},
    {"__mfc_trace",n_mfc_trace},
    {"__mfc_watch",n_mfc_watch},
    {"__k32_CreateFileA",g_file_CreateFileA},
    {"__k32_FindFirstFileA",g_file_FindFirstFileA},
    {"__mfc_guarded_call",n_guarded_call},
    {"__gu_LoadMenuFromModule",gu_LoadMenuFromModule},
    {"__gu_ImageListFromBitmap",gu_ImageListFromBitmap},
    {"__gu_ToolbarFromModule",gu_ToolbarFromModule},
    {"__gu_wsprintfA",gu_wsprintfA},
    {"__gu_LoadStringFromModule",gu_LoadStringFromModule},
    {"__gu_SetMenu",gu_SetMenu},
    GENERATED_FORWARDERS
    {"_Otsstrlen",n_Otsstrlen},{"_Otsstrcpy",n_Otsstrcpy},{"_Otsstrcmp",n_Otsstrcmp},
    {"_OtsZero",n_OtsZero},{"_OtsFill",n_OtsFill},{"_OtsMove",n_OtsMove},
    /* USER32 */
    {"__gu_RegisterClassA",gu_RegisterClassA},{"__gu_RegisterClassExA",gu_RegisterClassExA},
    {"__gu_CreateWindowExA",gu_CreateWindowExA},{"__gu_ShowWindow",gu_ShowWindow},
    {"__gu_UpdateWindow",gu_UpdateWindow},{"__gu_DestroyWindow",gu_DestroyWindow},
    {"__gu_DefWindowProcA",gu_DefWindowProcA},{"__gu_GetMessageA",gu_GetMessageA},
    {"__gu_PeekMessageA",gu_PeekMessageA},{"__gu_TranslateMessage",gu_TranslateMessage},
    {"__gu_DispatchMessageA",gu_DispatchMessageA},{"__gu_PostQuitMessage",gu_PostQuitMessage},
    {"__gu_PostMessageA",gu_PostMessageA},{"__gu_SendMessageA",gu_SendMessageA},
    {"__gu_BeginPaint",gu_BeginPaint},{"__gu_EndPaint",gu_EndPaint},
    {"__gu_GetClientRect",gu_GetClientRect},{"__gu_InvalidateRect",gu_InvalidateRect},
    {"__gu_FillRect",gu_FillRect},{"__gu_LoadCursorA",gu_LoadCursorA},
    {"__gu_LoadIconA",gu_LoadIconA},{"__gu_SetTimer",gu_SetTimer},
    {"__gu_KillTimer",gu_KillTimer},{"__gu_GetSystemMetrics",gu_GetSystemMetrics},
    {"__gu_MessageBoxA",gu_MessageBoxA},{"__gu_SetWindowTextA",gu_SetWindowTextA},
    {"__gu_MoveWindow",gu_MoveWindow},
    /* GDI32 */
    {"__gd_CreateSolidBrush",gd_CreateSolidBrush},{"__gd_DeleteObject",gd_DeleteObject},
    {"__gd_SetBkMode",gd_SetBkMode},{"__gd_SetTextColor",gd_SetTextColor},
    {"__gd_SetBkColor",gd_SetBkColor},{"__gd_TextOutA",gd_TextOutA},
    {"__gd_Ellipse",gd_Ellipse},{"__gd_Rectangle",gd_Rectangle},
    {"__gd_MoveToEx",gd_MoveToEx},{"__gd_LineTo",gd_LineTo},
    {"__gd_SelectObject",gd_SelectObject},{"__gd_CreatePen",gd_CreatePen},
    {"__gd_GetStockObject",gd_GetStockObject},{"__gd_SetPixel",gd_SetPixel},
    {NULL,NULL}
};

/* ------------------------------------------------------------ PE loading */
static int pe_load(Module*m,const char*path,int verbose)
{
    FILE*f=fopen(path,"rb"); if(!f){fprintf(stderr,"cannot open %s\n",path);return -1;}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    m->file=malloc((size_t)n); m->fsize=(size_t)n; m->path=path;
    if(fread(m->file,1,(size_t)n,f)!=(size_t)n){fclose(f);return -1;} fclose(f);
    if(RD16(m->file)!=0x5A4D){fprintf(stderr,"%s: not MZ\n",path);return -1;}
    uint32_t pe=RD32(m->file+0x3C); uint8_t*nt=m->file+pe;
    if(RD32(nt)!=0x00004550){fprintf(stderr,"%s: not PE\n",path);return -1;}
    if(RD16(nt+4)!=0x0284){fprintf(stderr,"%s: machine %#x not AXP64\n",path,RD16(nt+4));return -1;}
    uint16_t nsec=RD16(nt+6),ohsz=RD16(nt+20); uint8_t*oh=nt+24;
    if(RD16(oh)!=0x20B){fprintf(stderr,"%s: not PE32+\n",path);return -1;}
    m->entry=RD32(oh+16); m->base=RD64(oh+24); m->size=RD32(oh+56);
    uint32_t ndir=RD32(oh+108);
    for(uint32_t i=0;i<16&&i<ndir;i++){m->dir_rva[i]=RD32(oh+112+8*i);m->dir_size[i]=RD32(oh+112+8*i+4);}
    if(!guest_map(m->base,m->size,0)){fprintf(stderr,"%s: cannot map at %#llx\n",path,(unsigned long long)m->base);return -1;}
    memcpy((void*)(uintptr_t)m->base,m->file,RD32(oh+60));
    uint8_t*sh=nt+24+ohsz;
    for(int i=0;i<nsec;i++){uint8_t*s=sh+40*i;
        uint32_t vsize=RD32(s+8),rva=RD32(s+12),raw=RD32(s+16),poff=RD32(s+20);
        void*dst=(void*)(uintptr_t)(m->base+rva); memset(dst,0,vsize);
        if(raw&&poff) memcpy(dst,m->file+poff,raw<vsize?raw:vsize);
        if(verbose) printf("[winhost]   sect %-8.8s rva=%#08x vsz=%#08x raw=%#08x\n",(char*)s,rva,vsize,raw);
    }
    const char*bn=path,*q; for(q=path;*q;q++) if(*q=='/'||*q=='\\') bn=q+1;
    snprintf(m->name,sizeof m->name,"%s",bn);
    if(verbose) printf("[winhost] %s base=%#llx size=%#llx entry=%#llx\n",path,
        (unsigned long long)m->base,(unsigned long long)m->size,(unsigned long long)(m->base+m->entry));
    return 0;
}
static uint64_t pe_export(Module*m,const char*name){
    uint32_t rva=m->dir_rva[0]; if(!rva||!name) return 0;
    uint8_t*e=(uint8_t*)(uintptr_t)(m->base+rva);
    uint32_t nnames=RD32(e+24),afun=RD32(e+28),anam=RD32(e+32),aord=RD32(e+36);
    uint32_t*fun=(uint32_t*)(uintptr_t)(m->base+afun);
    uint32_t*nam=(uint32_t*)(uintptr_t)(m->base+anam);
    uint16_t*ord=(uint16_t*)(uintptr_t)(m->base+aord);
    for(uint32_t i=0;i<nnames;i++){const char*s=(const char*)(uintptr_t)(m->base+nam[i]);
        if(!strcmp(s,name)) return m->base+fun[ord[i]];}
    return 0;
}
static uint64_t pe_export_ord(Module*m,uint64_t ordinal){
    uint32_t rva=m->dir_rva[0]; if(!rva) return 0;
    uint8_t*e=(uint8_t*)(uintptr_t)(m->base+rva);
    uint32_t base_ord=RD32(e+16),nfun=RD32(e+20),afun=RD32(e+28);
    if(ordinal<base_ord||ordinal>=base_ord+nfun) return 0;
    uint32_t*fun=(uint32_t*)(uintptr_t)(m->base+afun);
    uint32_t fp=fun[ordinal-base_ord]; return fp?m->base+fp:0;
}
static int pe_bind_imports(Module*m,int verbose)
{
    uint32_t rva=m->dir_rva[1]; if(!rva) return 0;
    uint8_t*d=(uint8_t*)(uintptr_t)(m->base+rva);
    for(;;d+=20){
        uint32_t oft=RD32(d),name=RD32(d+12),ft=RD32(d+16);
        if(!name&&!ft) break;
        const char*dll=(const char*)(uintptr_t)(m->base+name);
        uint64_t*iat=(uint64_t*)(uintptr_t)(m->base+ft);
        uint64_t*hn=(uint64_t*)(uintptr_t)(m->base+(oft?oft:ft));
        for(int k=0;hn[k];k++){
            uint64_t ent=hn[k]; char sym[256]; uint64_t ordinal=0;
            if(ent&(1ULL<<63)){ordinal=ent&0xFFFF;snprintf(sym,sizeof sym,"#%llu",(unsigned long long)ordinal);}
            else snprintf(sym,sizeof sym,"%s",(const char*)(uintptr_t)(m->base+ent+2));
            uint64_t target=0;
            /* _Ots* are compiler helpers with a register-preservation
             * contract gcc cannot honour, so the native ones win even if a
             * guest module also exports them. */
            /* Host-resource entry points (files, registry, time) must come
             * from Wine even though our AXP64 KERNEL32 also exports some of
             * them, so that handles live in one space.  Guest-aware calls
             * (GetModuleHandle, GetProcAddress, LoadLibrary) stay in the
             * guest DLL, which is why this is a list and not a blanket rule. */
            static const char *prefer_native[] = {
                "FindFirstFileA","FindNextFileA","FindClose","GetFullPathNameA",
                "GetFileAttributesA","CreateFileA","ReadFile","SetFilePointer",
                "GetFileSize","CloseHandle","CreateFileMappingA","MapViewOfFile",
                "UnmapViewOfFile","GetFileInformationByHandle","GetFileType",
                "DeleteFileA","GetTempPathA","GetShortPathNameA",
                "GetWindowsDirectoryA","GetSystemDirectoryA",
                "ExpandEnvironmentStringsA","GetDriveTypeA","GetLogicalDrives",
                "GlobalAlloc","GlobalLock","GlobalUnlock","LocalFree",
                "GetSystemTimeAsFileTime","FileTimeToLocalFileTime",
                "FileTimeToSystemTime","CompareFileTime","GetDateFormatA",
                "GetTimeFormatA","FormatMessageA","GetLocaleInfoA",
                "GlobalMemoryStatus","GetComputerNameA", NULL };
            int helper = !strncmp(sym,"_Ots",4);
            for (int q=0; !helper && prefer_native[q]; q++)
                if (!strcmp(sym, prefer_native[q])) helper = 1;
            if(!helper)
                for(int i=0;i<nmods&&!target;i++){ if(&mods[i]==m) continue;
                    target=ordinal?pe_export_ord(&mods[i],ordinal):pe_export(&mods[i],sym);}
            const char*how="module";
            if(!target){ for(int i=0;builtin[i].name;i++) if(!strcmp(builtin[i].name,sym)){
                target=native_bind(builtin[i].name,builtin[i].fn); how="native"; break; } }
            if(!target){ char g[300]; snprintf(g,sizeof g,"__k32_%s",sym);
                for(int i=0;builtin[i].name;i++) if(!strcmp(builtin[i].name,g)){
                    target=native_bind(builtin[i].name,builtin[i].fn); how="wine"; break; } }
            if(!target){
                if(!keep_going){fprintf(stderr,"[winhost] unresolved import %s!%s\n",dll,sym);return -1;}
                /* fn == NULL means "not implemented yet": helper_native routes
                 * it to n_missing, which names it once and returns 0. */
                char nb[300]; snprintf(nb,sizeof nb,"%s!%s",dll,sym);
                target=native_bind(_strdup(nb),NULL); how="stub"; nmissing++;
            }
            iat[k]=target;
            if(verbose) printf("[winhost]   bind %s!%-22s -> %#llx (%s)\n",dll,sym,(unsigned long long)target,how);
        }
    }
    return 0;
}

/* driver: run a guest routine from the host to completion (DllMain, entry) */
static uint64_t run_guest_entry(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2)
{
    CPUAlpha *c=g_cpu;
    c->ireg[16]=a0; c->ireg[17]=a1; c->ireg[18]=a2;
    c->ireg[27]=fn; c->ireg[26]=RETURN_MAGIC; c->pc=fn;
    jit_run_until(&g_jit,c,RETURN_MAGIC,2000000000ULL);
    return c->ireg[0];
}

int main(int argc, char**argv)
{
    int verbose=0, argi=1;
    while(argi<argc && argv[argi][0]=='-'){
        if(!strcmp(argv[argi],"-v")) verbose=1;
        else if(!strcmp(argv[argi],"-k")) keep_going=1;
        else if(!strcmp(argv[argi],"-t")) trace_calls=1;
        else if(!strcmp(argv[argi],"-c")) ctl_trace=1;
        else if(!strcmp(argv[argi],"-C")) { ctl_trace=1; trace_calls=1; }
        argi++;
    }
    if(argi>=argc){fprintf(stderr,"usage: %s [-v|-k|-t] <img.exe> [dll...] [-- args]\n",argv[0]);return 2;}

    if(!guest_map(THUNK_BASE,MAX_NATIVE*THUNK_STRIDE,0) ||
       !guest_map(STACK_TOP-STACK_SIZE,STACK_SIZE,0) ||
       !guest_map(LIMBO_BASE,LIMBO_SIZE,0) ||
       !guest_map(HEAP_BASE,HEAP_SIZE,0)){
        fprintf(stderr,"guest_map failed for a fixed region\n"); return 1;
    }

    nmods=0;
    for(;argi<argc&&nmods<24;argi++){
        if(!strcmp(argv[argi],"--")){argi++;break;}
        if(pe_load(&mods[nmods],argv[argi],verbose)==0) nmods++; else return 1;
    }
    { size_t k=0;
      k+=(size_t)snprintf(guest_cmdline,sizeof guest_cmdline,"\"%s\"",nmods?mods[0].name:"app.exe");
      for(;argi<argc&&k+2<sizeof guest_cmdline;argi++)
        k+=(size_t)snprintf(guest_cmdline+k,sizeof guest_cmdline-k," %s",argv[argi]);
    }

    for(int i=0;i<nmods;i++) if(pe_bind_imports(&mods[i],verbose)!=0) return 1;
    if(nmissing) printf("[winhost] %d import(s) unresolved (running with -k)\n",nmissing);

    /* Window classes the guest's MFC creates by name live in host DLLs:
     * comctl32 (tree/list views) is linked in, and RichEdit 1.0 ("RICHEDIT",
     * what MFC 4.2's CRichEditView asks for) comes from riched32. */
    LoadLibraryA("riched32.dll");
    LoadLibraryA("riched20.dll");

    static CPUAlpha cpu; memset(&cpu,0,sizeof cpu); g_cpu=&cpu;
    if(jit_init(&g_jit,64u<<20,1u<<18)!=0){fprintf(stderr,"jit_init failed\n");return 1;}
    AddVectoredExceptionHandler(1,veh);

    cpu.ireg[30]=STACK_TOP-0x1000; cpu.fpcr=(2ULL<<58);

    for(int i=1;i<nmods;i++){
        if(!mods[i].entry) continue;
        uint64_t r=run_guest_entry(mods[i].base+mods[i].entry,mods[i].base,1,0);
        if(verbose) printf("[winhost] DllMain(%s,ATTACH)->%lld\n",mods[i].name,(long long)r);
        cpu.exit_code=0;
    }

    if(verbose) printf("[winhost] entering guest entry at %#llx\n",
        (unsigned long long)(mods[0].base+mods[0].entry));
    cpu.ireg[30]=STACK_TOP-0x1000;
    run_guest_entry(mods[0].base+mods[0].entry,0,0,0);

    if(cpu.exit_code==EXIT_UNIMPL){
        fprintf(stderr,"[winhost] unimplemented insn at %#llx: %08x\n",
            (unsigned long long)cpu.pc,*(uint32_t*)(uintptr_t)cpu.pc); return 3;
    }
    printf("[winhost] guest returned v0=%lld after %llu instructions\n",
        (long long)cpu.ireg[0],(unsigned long long)cpu.icount);
    return 0;
}
