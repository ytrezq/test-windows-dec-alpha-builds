/* axpwin - load an AXP64 (Machine 0x0284) PE image and run it under the
 * Alpha translator.
 *
 * This is the homogeneous model: everything the guest executes is Alpha
 * code, and the only native code sits at the very bottom, behind import
 * thunks — the same PE/Unix split modern Wine uses, where the PE-side DLLs
 * are guest-architecture and only the unixlib is host code.
 *
 * Imports are resolved against other loaded AXP64 modules first; anything
 * still unresolved is bound to a native stub through the PALcode call gate.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>
#include "emu.h"
#include "helpers.h"

/* --------------------------------------------------------------- memory */
void *guest_map(uint64_t addr, size_t len, int prot)
{
    uint64_t a = addr & ~0xFFFULL;
    size_t   l = (size_t)((addr - a) + len + 0xFFF) & ~0xFFFULL;
    void *p = mmap((void *)(uintptr_t)a, l, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    return p == MAP_FAILED ? NULL : (void *)(uintptr_t)addr;
}

/* ------------------------------------------------------- native bindings */
#define THUNK_BASE   0x7F000000ULL
#define THUNK_STRIDE 8
#define MAX_NATIVE   4096
#define STACK_TOP    0x20000000ULL
#define STACK_SIZE   0x00100000ULL
#define HEAP_BASE    0x30000000ULL
#define HEAP_SIZE    0x01000000ULL
#define RETURN_MAGIC 0x00000010ULL

typedef void (*NativeFn)(CPUAlpha *cpu);
static struct { const char *name; NativeFn fn; } natives[MAX_NATIVE];
static int n_natives;
static int trace_calls;
static char guest_cmdline[1024];

static uint64_t native_bind(const char *name, NativeFn fn)
{
    int i = n_natives++;
    natives[i].name = name;
    natives[i].fn   = fn;
    uint64_t addr = THUNK_BASE + (uint64_t)i * THUNK_STRIDE;
    /* opcode 0 (PALcode) is unused in user mode: it is our call gate */
    *(uint32_t *)(uintptr_t)addr = (uint32_t)i;
    *(uint32_t *)(uintptr_t)(addr + 4) = 0;
    return addr;
}

void helper_native(CPUAlpha *cpu, uint32_t insn)
{
    unsigned idx = insn & 0x03FFFFFF;
    if (idx >= (unsigned)n_natives || !natives[idx].fn) {
        fprintf(stderr, "[axpwin] unbound native thunk %u\n", idx);
        cpu->exit_code = EXIT_UNIMPL;
        return;
    }
    cpu->scratch0 = idx;
    cpu->ret_pc = cpu->ireg[26];            /* default: return to ra */
    if (trace_calls)
        fprintf(stderr, "[call] %-28s a0=%#llx a1=%#llx a2=%#llx\n", natives[idx].name,
                (unsigned long long)cpu->ireg[16], (unsigned long long)cpu->ireg[17],
                (unsigned long long)cpu->ireg[18]);
    natives[idx].fn(cpu);
}

/* argument/return helpers following the Alpha calling standard */
static uint64_t A(CPUAlpha *c, int n) { return c->ireg[16 + n]; }
static void     R(CPUAlpha *c, uint64_t v) { c->ireg[0] = v; }
static const char *gstr(uint64_t va) { return va ? (const char *)(uintptr_t)va : "(null)"; }

/* ---- a minimal bottom layer, standing in for the unixlib side ---------- */
static uint64_t heap_cursor = HEAP_BASE;

static void n_OutputDebugStringA(CPUAlpha *c) { fputs(gstr(A(c, 0)), stdout); }
static void n_GetTickCount(CPUAlpha *c)       { R(c, (uint64_t)(c->icount / 1000)); }
static void n_GetCurrentProcessId(CPUAlpha *c){ R(c, 0x1234); }
static void n_HeapAlloc(CPUAlpha *c)
{
    uint64_t n = (A(c, 0) + 15) & ~15ULL;
    uint64_t p = heap_cursor;
    if (p + n > HEAP_BASE + HEAP_SIZE) { R(c, 0); return; }
    heap_cursor += n;
    memset((void *)(uintptr_t)p, 0, n);
    R(c, p);
}
static void n_lstrlenA(CPUAlpha *c)
{ const char *s = gstr(A(c, 0)); R(c, s ? strlen(s) : 0); }
static void n_ExitProcess(CPUAlpha *c)
{ printf("[axpwin] ExitProcess(%llu)\n", (unsigned long long)A(c, 0));
  c->ireg[26] = RETURN_MAGIC; }

/* Unimplemented imports are bound to a thunk that names itself and stops the
 * guest, so a real application can be loaded and the exact set of missing
 * entry points inventoried. */
static void n_missing(CPUAlpha *c)
{
    unsigned idx = (unsigned)c->scratch0;        /* stashed by helper_native */
    fprintf(stderr, "[axpwin] guest called unimplemented import: %s\n",
            idx < (unsigned)n_natives ? natives[idx].name : "?");
    c->exit_code = EXIT_HALT;
}

/* ------------------------------------------------------------ PE image */
typedef struct {
    uint64_t base, size, entry;
    const char *path;
    char name[64];              /* basename, for GetModuleHandleA */
    uint8_t *file;
    size_t   fsize;
    uint32_t dir_rva[16], dir_size[16];
} Module;

#define RD16(p) (*(uint16_t *)(p))
#define RD32(p) (*(uint32_t *)(p))
#define RD64(p) (*(uint64_t *)(p))

static Module mods[16];
static int nmods;
static int keep_going, nmissing;
uint64_t pe_export(Module *m, const char *name);

/* ------- unixlib: the only host code the guest can reach -------------- */
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

static Module *find_module(const char *name)
{
    if (!name || !*name) return &mods[0];
    for (int i = 0; i < nmods; i++) if (!strcasecmp(mods[i].name, name)) return &mods[i];
    /* tolerate a missing or differing extension */
    for (int i = 0; i < nmods; i++) {
        const char *a = mods[i].name, *b = name;
        size_t la = strcspn(a, "."), lb = strcspn(b, ".");
        if (la == lb && !strncasecmp(a, b, la)) return &mods[i];
    }
    return NULL;
}
static Module *module_by_base(uint64_t b)
{
    if (!b) return &mods[0];
    for (int i = 0; i < nmods; i++) if (mods[i].base == b) return &mods[i];
    return NULL;
}
static uint64_t pe_export_ord(Module *m, uint64_t ordinal);


static void n_sys_write(CPUAlpha *c)
{ R(c, (uint64_t)write((int)A(c,0), (void *)(uintptr_t)A(c,1), (size_t)A(c,2))); }
static void n_sys_read(CPUAlpha *c)
{ R(c, (uint64_t)read((int)A(c,0), (void *)(uintptr_t)A(c,1), (size_t)A(c,2))); }
static void n_sys_open(CPUAlpha *c)
{ R(c, (uint64_t)(int64_t)open(gstr(A(c,0)), A(c,1) ? O_RDWR : O_RDONLY)); }
static void n_sys_close(CPUAlpha *c) { R(c, (uint64_t)close((int)A(c,0))); }
static void n_sys_seek(CPUAlpha *c)
{ R(c, (uint64_t)lseek((int)A(c,0), (off_t)(int64_t)A(c,1), (int)A(c,2))); }
static void n_sys_fsize(CPUAlpha *c)
{ struct stat st; R(c, fstat((int)A(c,0), &st) ? (uint64_t)-1 : (uint64_t)st.st_size); }
static void n_sys_mem(CPUAlpha *c)
{
    uint64_t n = (A(c,0) + 0xFFF) & ~0xFFFULL;
    uint64_t p = heap_cursor;
    if (p + n > HEAP_BASE + HEAP_SIZE) { R(c, 0); return; }
    heap_cursor += n;
    memset((void *)(uintptr_t)p, 0, n);
    R(c, p);
}
static void n_sys_ticks(CPUAlpha *c)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
  R(c, (uint64_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000)); }
static void n_sys_time(CPUAlpha *c) { R(c, (uint64_t)time(NULL)); }
static void n_sys_exit(CPUAlpha *c)
{ printf("[axpwin] guest exit(%lld)\n", (long long)A(c,0)); c->ireg[26] = RETURN_MAGIC; }
static void n_sys_debug(CPUAlpha *c) { fputs(gstr(A(c,0)), stdout); fflush(stdout); }
static void n_sys_cmdline(CPUAlpha *c)
{
    char *buf = (char *)(uintptr_t)A(c, 0);
    uint64_t n = A(c, 1);
    if (!buf || !n) { R(c, 0); return; }
    snprintf(buf, (size_t)n, "%s", guest_cmdline);
    R(c, strlen(buf));
}
static int pe_load(Module *m, const char *path, int verbose);
static int pe_bind_imports(Module *m, Module *mods_, int nmods_, int verbose);

/* LoadLibrary at run time: map the PE and bind its imports, exactly as the
 * startup path does.  This is what lets the original depends.dll walk a
 * module from inside the guest. */
static void n_sys_load(CPUAlpha *c)
{
    const char *path = gstr(A(c, 0));
    Module *m = find_module(path);
    if (m) { R(c, m->base); return; }
    if (nmods >= 16) { R(c, 0); return; }
    if (pe_load(&mods[nmods], strdup(path), 0) != 0) {
        fprintf(stderr, "[axpwin] guest LoadLibrary(\"%s\") FAILED\n", path);
        R(c, 0); return;
    }
    nmods++;
    if (pe_bind_imports(&mods[nmods - 1], mods, nmods, 0) != 0) { R(c, 0); return; }
    printf("[axpwin] guest loaded %s at %#llx\n", path,
           (unsigned long long)mods[nmods - 1].base);
    R(c, mods[nmods - 1].base);
}
static void n_sys_module_base(CPUAlpha *c)
{ Module *m = find_module(A(c,0) ? gstr(A(c,0)) : NULL); R(c, m ? m->base : 0); }
static void n_sys_module_path(CPUAlpha *c)
{
    Module *m = module_by_base(A(c,0));
    char *buf = (char *)(uintptr_t)A(c,1);
    uint64_t n = A(c,2);
    if (!m || !buf || !n) { R(c, 0); return; }
    char tmp[512];
    snprintf(tmp, sizeof tmp, "C:\\%s", m->name);
    snprintf(buf, (size_t)n, "%s", tmp);
    R(c, strlen(buf));
}
static void n_sys_module_proc(CPUAlpha *c)
{
    Module *m = module_by_base(A(c,0));
    if (!m) { R(c, 0); return; }
    R(c, A(c,1) ? pe_export(m, gstr(A(c,1))) : pe_export_ord(m, A(c,2)));
}

/* The Alpha has no integer divide instruction, so the compiler calls these.
 * They use their own convention: operands in t10/t11 ($24/$25), result in
 * t12 ($27), return through t9 ($23), and every other register preserved. */
#define DIVHELPER(NAME, EXPR)                                        \
    static void NAME(CPUAlpha *c)                                    \
    {                                                                \
        uint64_t a = c->ireg[24], b = c->ireg[25];                   \
        c->ireg[27] = (EXPR);                                        \
        c->ret_pc = c->ireg[23];                                     \
    }
DIVHELPER(n_divl,  b ? (uint64_t)(int64_t)(int32_t)((int32_t)a / (int32_t)b) : 0)
DIVHELPER(n_divlu, b ? (uint64_t)(int64_t)(int32_t)((uint32_t)a / (uint32_t)b) : 0)
DIVHELPER(n_reml,  b ? (uint64_t)(int64_t)(int32_t)((int32_t)a % (int32_t)b) : 0)
DIVHELPER(n_remlu, b ? (uint64_t)(int64_t)(int32_t)((uint32_t)a % (uint32_t)b) : 0)
DIVHELPER(n_divq,  b ? (uint64_t)((int64_t)a / (int64_t)b) : 0)
DIVHELPER(n_divqu, b ? a / b : 0)
DIVHELPER(n_remq,  b ? (uint64_t)((int64_t)a % (int64_t)b) : 0)
DIVHELPER(n_remqu, b ? a % b : 0)

static const struct { const char *name; NativeFn fn; } builtin[] = {
    { "__divl",  n_divl },  { "__divlu", n_divlu },
    { "__reml",  n_reml },  { "__remlu", n_remlu },
    { "__divq",  n_divq },  { "__divqu", n_divqu },
    { "__remq",  n_remq },  { "__remqu", n_remqu },
    { "__sys_write",        n_sys_write },
    { "__sys_read",         n_sys_read },
    { "__sys_open",         n_sys_open },
    { "__sys_close",        n_sys_close },
    { "__sys_seek",         n_sys_seek },
    { "__sys_fsize",        n_sys_fsize },
    { "__sys_mem",          n_sys_mem },
    { "__sys_ticks",        n_sys_ticks },
    { "__sys_time",         n_sys_time },
    { "__sys_exit",         n_sys_exit },
    { "__sys_debug",        n_sys_debug },
    { "__sys_cmdline",      n_sys_cmdline },
    { "__sys_load",         n_sys_load },
    { "__sys_module_base",  n_sys_module_base },
    { "__sys_module_path",  n_sys_module_path },
    { "__sys_module_proc",  n_sys_module_proc },
    { "OutputDebugStringA",   n_OutputDebugStringA },
    { "GetTickCount",         n_GetTickCount },
    { "GetCurrentProcessId",  n_GetCurrentProcessId },
    { "HeapAlloc",            n_HeapAlloc },
    { "lstrlenA",             n_lstrlenA },
    { "ExitProcess",          n_ExitProcess },
    { NULL, NULL }
};

/* ------------------------------------------------------------ PE loading */

static int pe_load(Module *m, const char *path, int verbose)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    m->file = malloc((size_t)n); m->fsize = (size_t)n; m->path = path;
    if (fread(m->file, 1, (size_t)n, f) != (size_t)n) { fclose(f); return -1; }
    fclose(f);

    if (RD16(m->file) != 0x5A4D) { fprintf(stderr, "%s: not MZ\n", path); return -1; }
    uint32_t pe = RD32(m->file + 0x3C);
    uint8_t *nt = m->file + pe;
    if (RD32(nt) != 0x00004550) { fprintf(stderr, "%s: not PE\n", path); return -1; }
    uint16_t machine = RD16(nt + 4);
    if (machine != 0x0284) {
        fprintf(stderr, "%s: machine %#x is not AXP64 (0x284)\n", path, machine);
        return -1;
    }
    uint16_t nsec  = RD16(nt + 6);
    uint16_t ohsz  = RD16(nt + 20);
    uint8_t *oh    = nt + 24;
    if (RD16(oh) != 0x20B) { fprintf(stderr, "%s: not PE32+\n", path); return -1; }
    m->entry = RD32(oh + 16);
    m->base  = RD64(oh + 24);
    m->size  = RD32(oh + 56);
    uint32_t ndir = RD32(oh + 108);
    for (uint32_t i = 0; i < 16 && i < ndir; i++) {
        m->dir_rva[i]  = RD32(oh + 112 + 8 * i);
        m->dir_size[i] = RD32(oh + 112 + 8 * i + 4);
    }
    if (!guest_map(m->base, m->size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        fprintf(stderr, "%s: cannot map image at %#llx\n", path,
                (unsigned long long)m->base);
        return -1;
    }
    memcpy((void *)(uintptr_t)m->base, m->file, RD32(oh + 60));   /* headers */
    uint8_t *sh = nt + 24 + ohsz;
    for (int i = 0; i < nsec; i++) {
        uint8_t *s = sh + 40 * i;
        uint32_t vsize = RD32(s + 8), rva = RD32(s + 12);
        uint32_t raw = RD32(s + 16), poff = RD32(s + 20);
        void *dst = (void *)(uintptr_t)(m->base + rva);
        memset(dst, 0, vsize);
        if (raw && poff) memcpy(dst, m->file + poff, raw < vsize ? raw : vsize);
        if (verbose)
            printf("[axpwin]   section %-8.8s rva=%#08x vsize=%#08x raw=%#08x\n",
                   (char *)s, rva, vsize, raw);
    }
    const char *bn = path, *q;
    for (q = path; *q; q++) if (*q == '/' || *q == '\\') bn = q + 1;
    snprintf(m->name, sizeof m->name, "%s", bn);
    if (verbose)
        printf("[axpwin] %s: base=%#llx size=%#llx entry=%#llx\n", path,
               (unsigned long long)m->base, (unsigned long long)m->size,
               (unsigned long long)(m->base + m->entry));
    return 0;
}

/* Find an exported symbol in an already-loaded module. */
uint64_t pe_export(Module *m, const char *name)
{
    uint32_t rva = m->dir_rva[0];
    if (!rva) return 0;
    uint8_t *e = (uint8_t *)(uintptr_t)(m->base + rva);
    uint32_t nnames = RD32(e + 24);
    uint32_t afun = RD32(e + 28), anam = RD32(e + 32), aord = RD32(e + 36);
    uint32_t *fun = (uint32_t *)(uintptr_t)(m->base + afun);
    uint32_t *nam = (uint32_t *)(uintptr_t)(m->base + anam);
    uint16_t *ord = (uint16_t *)(uintptr_t)(m->base + aord);
    for (uint32_t i = 0; i < nnames; i++) {
        const char *s = (const char *)(uintptr_t)(m->base + nam[i]);
        if (!strcmp(s, name)) return m->base + fun[ord[i]];
    }
    return 0;
}

static int pe_bind_imports(Module *m, Module *mods_, int nmods_, int verbose)
{
    (void)mods_; (void)nmods_;
    uint32_t rva = m->dir_rva[1];
    if (!rva) return 0;
    uint8_t *d = (uint8_t *)(uintptr_t)(m->base + rva);
    for (;; d += 20) {
        uint32_t oft = RD32(d), name = RD32(d + 12), ft = RD32(d + 16);
        if (!name && !ft) break;
        const char *dll = (const char *)(uintptr_t)(m->base + name);
        uint64_t *iat = (uint64_t *)(uintptr_t)(m->base + ft);
        uint64_t *hn  = (uint64_t *)(uintptr_t)(m->base + (oft ? oft : ft));
        for (int k = 0; hn[k]; k++) {
            uint64_t ent = hn[k];
            char sym[256];
            uint64_t ordinal = 0;
            if (ent & (1ULL << 63)) {
                ordinal = ent & 0xFFFF;
                snprintf(sym, sizeof sym, "#%llu", (unsigned long long)ordinal);
            } else {
                snprintf(sym, sizeof sym, "%s",
                         (const char *)(uintptr_t)(m->base + ent + 2));
            }
            uint64_t target = 0;
            for (int i = 0; i < nmods && !target; i++) {
                if (&mods[i] == m) continue;
                target = ordinal ? pe_export_ord(&mods[i], ordinal)
                                 : pe_export(&mods[i], sym);
            }
            const char *how = "module";
            if (!target) {
                for (int i = 0; builtin[i].name; i++)
                    if (!strcmp(builtin[i].name, sym)) {
                        target = native_bind(builtin[i].name, builtin[i].fn);
                        how = "native"; break;
                    }
            }
            if (!target) {
                if (!keep_going) {
                    fprintf(stderr, "[axpwin] unresolved import %s!%s\n", dll, sym);
                    return -1;
                }
                target = native_bind(strdup(sym), n_missing);
                how = "MISSING";
                nmissing++;
            }
            iat[k] = target;
            if (verbose)
                printf("[axpwin]   bind %s!%-22s -> %#llx (%s)\n", dll, sym,
                       (unsigned long long)target, how);
        }
    }
    return 0;
}

/* Call a guest routine and return when it does.  Used for DllMain and for
 * anything else the host needs to drive inside the AXP64 world. */
static uint64_t guest_call(JitCtx *j, CPUAlpha *cpu, uint64_t fn,
                           uint64_t a0, uint64_t a1, uint64_t a2)
{
    uint64_t save_pc = cpu->pc, save_ra = cpu->ireg[26], save_pv = cpu->ireg[27];
    cpu->ireg[16] = a0; cpu->ireg[17] = a1; cpu->ireg[18] = a2;
    cpu->ireg[27] = fn;                 /* pv, for gcc-style prologues */
    cpu->ireg[26] = RETURN_MAGIC;
    cpu->pc = fn;
    jit_run_until(j, cpu, RETURN_MAGIC, 200000000ULL);
    uint64_t r = cpu->ireg[0];
    cpu->pc = save_pc; cpu->ireg[26] = save_ra; cpu->ireg[27] = save_pv;
    return r;
}

/* --------------------------------------------------------- fault reports */
static CPUAlpha *g_cpu;

static void fault_handler(int sig, siginfo_t *si, void *uc)
{
    (void)uc;
    fprintf(stderr,
            "\n[axpwin] guest fault (%s) accessing %p\n"
            "         current guest block pc = %#llx, last import = %s\n"
            "         after %llu guest instructions\n",
            sig == SIGSEGV ? "SIGSEGV" : "SIGBUS", si->si_addr,
            g_cpu ? (unsigned long long)g_cpu->scratch1 : 0ULL,
            (g_cpu && g_cpu->scratch0 < (uint64_t)n_natives)
                ? natives[g_cpu->scratch0].name : "(none)",
            g_cpu ? (unsigned long long)g_cpu->icount : 0ULL);
    if (g_cpu) {
        fprintf(stderr, "         a0=%#llx a1=%#llx a2=%#llx sp=%#llx ra=%#llx\n",
                (unsigned long long)g_cpu->ireg[16], (unsigned long long)g_cpu->ireg[17],
                (unsigned long long)g_cpu->ireg[18], (unsigned long long)g_cpu->ireg[30],
                (unsigned long long)g_cpu->ireg[26]);
    }
    _exit(5);
}

/* ------------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    int verbose = 0, argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-v")) verbose = 1;
        else if (!strcmp(argv[argi], "-k")) keep_going = 1;
        else if (!strcmp(argv[argi], "-t")) trace_calls = 1;
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-v] <image.exe|dll> [more modules...]\n", argv[0]);
        return 2;
    }
    if (!guest_map(THUNK_BASE, MAX_NATIVE * THUNK_STRIDE, PROT_READ | PROT_WRITE | PROT_EXEC) ||
        !guest_map(STACK_TOP - STACK_SIZE, STACK_SIZE, PROT_READ | PROT_WRITE) ||
        !guest_map(HEAP_BASE, HEAP_SIZE, PROT_READ | PROT_WRITE)) {
        perror("guest_map"); return 1;
    }

    nmods = 0;
    for (; argi < argc && nmods < 16; argi++) {
        if (!strcmp(argv[argi], "--")) { argi++; break; }
        if (pe_load(&mods[nmods], argv[argi], verbose) == 0) nmods++;
        else return 1;
    }
    /* whatever follows "--" is the guest's command line */
    {
        size_t k = 0;
        k += (size_t)snprintf(guest_cmdline, sizeof guest_cmdline, "\"%s\"",
                              nmods ? mods[0].name : "app.exe");
        for (; argi < argc && k + 2 < sizeof guest_cmdline; argi++)
            k += (size_t)snprintf(guest_cmdline + k, sizeof guest_cmdline - k, " %s", argv[argi]);
    }

    for (int i = 0; i < nmods; i++)
        if (pe_bind_imports(&mods[i], mods, nmods, verbose) != 0) return 1;
    if (nmissing)
        printf("[axpwin] %d import(s) have no AXP64 implementation yet\n", nmissing);

    static CPUAlpha cpu;
    memset(&cpu, 0, sizeof cpu);
    g_cpu = &cpu;
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault_handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    cpu.pc        = mods[0].base + mods[0].entry;
    cpu.ireg[27]  = cpu.pc;                 /* pv: the GPLOAD prologue needs it */
    cpu.ireg[26]  = RETURN_MAGIC;           /* ra: where a final `ret` lands */
    cpu.ireg[30]  = STACK_TOP - 0x1000;     /* sp */
    cpu.fpcr      = (2ULL << 58);

    JitCtx jit;
    if (jit_init(&jit, 64u << 20, 1u << 18) != 0) { perror("jit_init"); return 1; }

    /* DLL_PROCESS_ATTACH for every module but the image itself, in load
     * order.  depends.dll initialises its hook state here. */
    for (int i = 1; i < nmods; i++) {
        if (!mods[i].entry) continue;
        uint64_t r = guest_call(&jit, &cpu, mods[i].base + mods[i].entry,
                                mods[i].base, 1 /* DLL_PROCESS_ATTACH */, 0);
        if (verbose)
            printf("[axpwin] DllMain(%s, DLL_PROCESS_ATTACH) -> %lld\n",
                   mods[i].name, (long long)r);
        if (cpu.exit_code) { cpu.exit_code = 0; }
    }

    if (verbose) printf("[axpwin] entering guest at %#llx\n",
                        (unsigned long long)cpu.pc);
    jit_run_until(&jit, &cpu, RETURN_MAGIC, 200000000ULL);

    if (cpu.exit_code == EXIT_UNIMPL) {
        fprintf(stderr, "[axpwin] unimplemented instruction at %#llx: %08x\n",
                (unsigned long long)cpu.pc, *(uint32_t *)(uintptr_t)cpu.pc);
        return 3;
    }
    if (cpu.exit_code == EXIT_HALT) {
        fprintf(stderr, "[axpwin] halted at pc=%#llx after %llu instructions\n",
                (unsigned long long)cpu.pc, (unsigned long long)cpu.icount);
        return 4;
    }
    printf("[axpwin] guest returned v0=%lld after %llu instructions\n",
           (long long)cpu.ireg[0], (unsigned long long)cpu.icount);
    return 0;
}

/* Export lookup by ordinal (MFC42 imports everything this way). */
static uint64_t pe_export_ord(Module *m, uint64_t ordinal)
{
    uint32_t rva = m->dir_rva[0];
    if (!rva) return 0;
    uint8_t *e = (uint8_t *)(uintptr_t)(m->base + rva);
    uint32_t base_ord = RD32(e + 16), nfun = RD32(e + 20), afun = RD32(e + 28);
    if (ordinal < base_ord || ordinal >= base_ord + nfun) return 0;
    uint32_t *fun = (uint32_t *)(uintptr_t)(m->base + afun);
    uint32_t f = fun[ordinal - base_ord];
    return f ? m->base + f : 0;
}
