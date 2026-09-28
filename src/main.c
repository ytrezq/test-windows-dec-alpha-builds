/* Test driver: run a flat block of Alpha instructions under the translator
 * with a given initial register state, then dump the final state.
 * Used for differential testing against qemu-alpha. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "emu.h"

#define TEST_DATA_ADDR 0x10000000ULL
#define TEST_DATA_SIZE 0x100000ULL

void *guest_map(uint64_t addr, size_t len, int prot)
{
    void *p = mmap((void *)(uintptr_t)addr, len, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* state file layout: 32 ireg, 32 freg, fpcr  (all little-endian uint64) */
#define STATE_WORDS 65

static int read_all(const char *path, void *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
          "usage: %s <flat.bin> <loadaddr-hex> <state-in> <state-out> [maxinsn]\n", argv[0]);
        return 2;
    }
    uint64_t load = strtoull(argv[2], NULL, 16);
    uint64_t maxinsn = argc > 5 ? strtoull(argv[5], NULL, 0) : 1000000;
    uint64_t entry   = argc > 6 ? strtoull(argv[6], NULL, 16) : 0;

    /* code region */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open code"); return 1; }
    fseek(f, 0, SEEK_END); long csize = ftell(f); fseek(f, 0, SEEK_SET);
    uint64_t cbase = load & ~0xFFFULL;
    size_t   clen  = (size_t)((load - cbase) + csize + 0x2000) & ~0xFFFULL;
    void *cp = guest_map(cbase, clen, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!cp) { perror("map code"); return 1; }
    if (fread((void *)(uintptr_t)load, 1, (size_t)csize, f) != (size_t)csize) return 1;
    fclose(f);

    /* data region used by memory tests */
    if (!guest_map(TEST_DATA_ADDR, TEST_DATA_SIZE, PROT_READ | PROT_WRITE)) {
        perror("map data"); return 1;
    }

    uint64_t st[STATE_WORDS];
    memset(st, 0, sizeof st);
    if (read_all(argv[3], st, sizeof st) != 0) { perror("state-in"); return 1; }

    static CPUAlpha cpu;
    memset(&cpu, 0, sizeof cpu);
    for (int i = 0; i < 32; i++) cpu.ireg[i] = st[i];
    for (int i = 0; i < 32; i++) cpu.freg[i] = st[32 + i];
    cpu.fpcr = st[64];
    cpu.ireg[31] = 0; cpu.freg[31] = 0;
    cpu.pc = entry ? entry : load;

    /* Deterministic pattern in the first 4 KiB of the data region; the
     * qemu reference harness fills the same bytes, so stores are compared. */
    unsigned char *db = (unsigned char *)(uintptr_t)TEST_DATA_ADDR;
    for (int i = 0; i < 4096; i++) db[i] = (unsigned char)((i * 167 + 13) & 0xFF);

    JitCtx jit;
    if (jit_init(&jit, 64u << 20, 1u << 18) != 0) { perror("jit_init"); return 1; }
    jit.xlat_lo = load;
    jit.xlat_hi = load + (uint64_t)csize;

    jit_run(&jit, &cpu, load, load + (uint64_t)csize, maxinsn);

    uint64_t out[STATE_WORDS + 2];
    for (int i = 0; i < 32; i++) out[i] = cpu.ireg[i];
    for (int i = 0; i < 32; i++) out[32 + i] = cpu.freg[i];
    out[64] = cpu.fpcr;
    out[65] = cpu.exit_code;
    out[66] = cpu.pc;
    FILE *o = fopen(argv[4], "wb");
    if (!o) { perror("state-out"); return 1; }
    fwrite(out, 1, 65 * 8, o);          /* ireg, freg, fpcr  (reference layout) */
    fwrite(db, 1, 4096, o);             /* data buffer */
    fwrite(&out[65], 1, 16, o);         /* exit_code, pc (emulator only) */
    fclose(o);

    if (cpu.exit_code == EXIT_UNIMPL)
        fprintf(stderr, "UNIMPL at pc=%#llx insn=%08x\n",
                (unsigned long long)cpu.pc, *(uint32_t *)(uintptr_t)cpu.pc);
    return 0;
}
