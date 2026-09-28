#!/usr/bin/env python3
"""elf2pe - repackage a linked Alpha ELF image as a Windows AXP64 PE32+.

There is no Alpha-PE assembler or linker in existence any more, and LLVM
dropped its Alpha backend in 3.0, so the only route from C to AXP64 machine
code is alpha-linux-gnu-gcc.  Rather than write an Alpha linker, we let
alpha-linux-gnu-ld resolve every Alpha relocation (GPDISP / LITERAL /
GPREL*) against a fixed image base and then wrap the resulting image in a
PE container.

The compiler already reaches external symbols indirectly, through 64-bit
GOT slots addressed off gp.  Those slots are exactly what a PE import
address table is, so the PE import directory simply points its FirstThunk
at them and the loader fills them in.

Format decisions were checked against depends.dll, a genuine AXP64 DLL
(Machine 0x0284, PE32+ magic 0x20B, 240-byte optional header, 8-byte IAT
entries, section alignment 0x2000).
"""
import argparse, struct, subprocess, sys

IMAGE_FILE_MACHINE_ALPHA64 = 0x0284
R_ALPHA_LITERAL = 4

SEC_CODE    = 0x60000020   # code, execute, read
SEC_RDATA   = 0x40000040   # initialised data, read
SEC_DATA    = 0xC0000040   # initialised data, read, write
SEC_BSS     = 0xC0000080   # uninitialised data, read, write

# ------------------------------------------------------------------ ELF
class Elf:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        assert self.d[:4] == b"\x7fELF" and self.d[4] == 2 and self.d[5] == 1, "need 64-bit LE ELF"
        (self.e_type, self.e_machine, _, self.e_entry, self.e_phoff, self.e_shoff,
         _, _, _, _, self.e_shentsize, self.e_shnum, self.e_shstrndx) = \
            struct.unpack_from("<HHIQQQIHHHHHH", self.d, 16)
        assert self.e_machine == 0x9026, f"not an Alpha ELF (machine={self.e_machine:#x})"
        self.sections = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            name, typ, flags, addr, off, size, link, info, align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", self.d, o)
            self.sections.append(dict(name_off=name, type=typ, flags=flags, addr=addr,
                                      off=off, size=size, link=link, info=info,
                                      align=align, entsize=entsize, idx=i))
        strtab = self.sections[self.e_shstrndx]
        for s in self.sections:
            s["name"] = self._cstr(strtab["off"] + s["name_off"])

    def _cstr(self, off):
        e = self.d.index(b"\0", off)
        return self.d[off:e].decode()

    def sec(self, name):
        for s in self.sections:
            if s["name"] == name: return s
        return None

    def data(self, s):
        if s["type"] == 8:  # SHT_NOBITS
            return b"\0" * s["size"]
        return self.d[s["off"]:s["off"] + s["size"]]

    def symbols(self):
        out = []
        symtab = self.sec(".symtab")
        if not symtab: return out
        strtab = self.sections[symtab["link"]]
        n = symtab["size"] // 24
        for i in range(n):
            o = symtab["off"] + i * 24
            nameoff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.d, o)
            out.append(dict(name=self._cstr(strtab["off"] + nameoff), info=info,
                            shndx=shndx, value=value, size=size, idx=i))
        return out

    def relocs(self, secname):
        """R_ALPHA_* entries of .rela<secname> (requires ld --emit-relocs)."""
        rs = self.sec(".rela" + secname)
        if not rs: return []
        symtab = self.sections[rs["link"]]
        strtab = self.sections[symtab["link"]]
        out = []
        for i in range(rs["size"] // 24):
            o = rs["off"] + i * 24
            off, info, addend = struct.unpack_from("<QQq", self.d, o)
            sym, typ = info >> 32, info & 0xFFFFFFFF
            so = symtab["off"] + sym * 24
            nameoff = struct.unpack_from("<I", self.d, so)[0]
            out.append(dict(off=off, sym=sym, type=typ, addend=addend,
                            symname=self._cstr(strtab["off"] + nameoff)))
        return out

# --------------------------------------------------- GOT slot discovery
def find_got_slots(elf, gp):
    """symbol name -> absolute address of the GOT slot holding it.

    Each R_ALPHA_LITERAL marks an `ldq Rx, disp(gp)' that loads a symbol's
    address; the slot is gp + disp."""
    slots = {}
    for sname in (".text", ".rodata", ".data"):
        sec = elf.sec(sname)
        if not sec: continue
        base = sec["addr"]
        blob = elf.data(sec)
        for r in elf.relocs(sname):
            if r["type"] != R_ALPHA_LITERAL: continue
            insn_off = r["off"] - base
            if not (0 <= insn_off < len(blob)): continue
            insn = struct.unpack_from("<I", blob, insn_off)[0]
            disp = struct.unpack("<h", struct.pack("<H", insn & 0xFFFF))[0]
            rb = (insn >> 16) & 31
            if rb != 29:            # must be gp-relative
                continue
            if r["symname"]:                       # skip section symbols
                slots.setdefault(r["symname"], gp + disp)
    return slots

# ------------------------------------------------------------------ PE
def align_up(v, a): return (v + a - 1) & ~(a - 1)

class PEBuilder:
    def __init__(self, base, sect_align=0x2000, file_align=0x200):
        self.base, self.sa, self.fa = base, sect_align, file_align
        self.sections = []      # (name, rva, vsize, data, characteristics)

    def add(self, name, rva, data, vsize, chars):
        self.sections.append([name, rva, vsize, data, chars])

    def build(self, entry_rva, is_dll, dirs, subsystem=3):
        self.sections.sort(key=lambda s: s[1])
        nsec = len(self.sections)
        hdr_size = align_up(0x40 + 0x40 + 4 + 20 + 240 + 40 * nsec, self.fa)

        # assign file offsets
        foff = hdr_size
        for s in self.sections:
            raw = align_up(len(s[3]), self.fa)
            s.append(foff if raw else 0)          # s[5] = file offset
            s.append(raw)                         # s[6] = raw size
            foff += raw

        image_size = align_up(max(s[1] + s[2] for s in self.sections), self.sa)
        code = [s for s in self.sections if s[4] & 0x20]
        idata = [s for s in self.sections if s[4] & 0x40]
        size_code = sum(align_up(s[2], self.fa) for s in code)
        size_data = sum(align_up(s[2], self.fa) for s in idata)
        base_code = min([s[1] for s in code], default=0)

        out = bytearray()
        # --- DOS header + stub
        dos = bytearray(0x40)
        struct.pack_into("<H", dos, 0, 0x5A4D)
        struct.pack_into("<I", dos, 0x3C, 0x80)   # PE signature follows the 64-byte stub
        out += dos
        stub = bytearray(0x40)
        stub[:len(b"This program cannot be run in DOS mode.")] = b"This program cannot be run in DOS mode."
        out += stub
        # --- PE signature + COFF header
        out += b"PE\0\0"
        chars = 0x0002 | 0x0004 | 0x0008 | 0x0020   # EXECUTABLE|LINES_STRIPPED|SYMS_STRIPPED|LARGE_ADDRESS_AWARE
        if is_dll: chars |= 0x2000
        out += struct.pack("<HHIIIHH", IMAGE_FILE_MACHINE_ALPHA64, nsec, 0x39F08B1A,
                           0, 0, 240, chars)
        # --- optional header (PE32+)
        # PE32+ standard fields: no BaseOfData (unlike PE32)
        oh = struct.pack("<HBBIIIII",
                         0x20B, 6, 20,                 # magic, linker major/minor
                         size_code, size_data, 0,
                         entry_rva, base_code)
        oh += struct.pack("<QIIHHHHHHIIIIHH",
                          self.base, self.sa, self.fa,
                          4, 0,        # OS version
                          0, 0,        # image version
                          4, 0,        # subsystem version
                          0,           # win32 version
                          image_size, hdr_size, 0,
                          subsystem, 0)
        oh += struct.pack("<QQQQII", 0x100000, 0x2000, 0x100000, 0x2000, 0, 16)
        dirtab = bytearray(16 * 8)
        for i, (rva, size) in dirs.items():
            struct.pack_into("<II", dirtab, i * 8, rva, size)
        oh += bytes(dirtab)
        assert len(oh) == 240, len(oh)
        out += oh
        # --- section headers
        for name, rva, vsize, data, ch, fo, raw in self.sections:
            out += struct.pack("<8sIIIIIIHHI", name.encode()[:8], vsize, rva,
                               raw, fo, 0, 0, 0, 0, ch)
        out += b"\0" * (hdr_size - len(out))
        # --- section bodies
        for name, rva, vsize, data, ch, fo, raw in self.sections:
            if raw:
                out += data + b"\0" * (raw - len(data))
        return bytes(out)

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("out")
    ap.add_argument("--dll", action="store_true")
    ap.add_argument("--entry", default=None, help="entry symbol (default: ELF entry)")
    ap.add_argument("--export", action="append", default=[],
                    help="EXPNAME[=symbol][:data] to export (repeatable). "
                         "':data' exports the address directly instead of "
                         "going through a pv-setup thunk.")
    ap.add_argument("--import", dest="imports", action="append", default=[],
                    help="DLL.dll:sym1,sym2 (repeatable)")
    ap.add_argument("--export-ord", action="append", default=[],
                    help="ORD=symbol : export at a fixed ordinal with no name "
                         "(how MFC42 exports everything). Repeatable, and may "
                         "be given as a file with @path.")
    ap.add_argument("--subsystem", type=int, default=3)
    args = ap.parse_args()

    elf = Elf(args.elf)
    syms = {s["name"]: s for s in elf.symbols() if s["name"]}
    base = min(s["addr"] for s in elf.sections if s["flags"] & 0x2 and s["addr"])
    base &= ~0xFFFF                       # PE image base must be 64 KiB aligned

    got = elf.sec(".got")
    gp = syms["_gp"]["value"] if "_gp" in syms else (got["addr"] + 0x8000 if got else 0)
    slots = find_got_slots(elf, gp)

    # ---- collect allocated sections -> PE sections
    peb = PEBuilder(base)
    name_map = {".text": (".text", SEC_CODE), ".rodata": (".rdata", SEC_RDATA),
                ".data": (".data", SEC_DATA), ".got": (".data", SEC_DATA),
                ".sdata": (".data", SEC_DATA), ".bss": (".bss", SEC_BSS),
                ".sbss": (".bss", SEC_BSS)}
    groups = {}
    for s in elf.sections:
        if not (s["flags"] & 0x2) or s["size"] == 0:   # SHF_ALLOC
            continue
        pename, ch = name_map.get(s["name"], (".data", SEC_DATA))
        g = groups.setdefault(pename, dict(ch=ch, lo=s["addr"], hi=s["addr"] + s["size"], parts=[]))
        g["lo"] = min(g["lo"], s["addr"]); g["hi"] = max(g["hi"], s["addr"] + s["size"])
        g["ch"] = g["ch"] | ch if pename != ".bss" else ch
        g["parts"].append(s)

    # contiguous blob per PE section
    for pename, g in groups.items():
        size = g["hi"] - g["lo"]
        blob = bytearray(size)
        nobits = True
        for s in g["parts"]:
            if s["type"] != 8:
                nobits = False
                blob[s["addr"] - g["lo"]: s["addr"] - g["lo"] + s["size"]] = elf.data(s)
        g["rva"] = g["lo"] - base
        g["blob"] = b"" if nobits else bytes(blob)
        g["vsize"] = size

    # ---- import directory -------------------------------------------------
    imports = []
    for spec in args.imports:
        dll, _, names = spec.partition(":")
        imports.append((dll, [n for n in names.split(",") if n]))

    idata_rva = align_up(max(g["rva"] + g["vsize"] for g in groups.values()), peb.sa)

    blobs = bytearray()
    def put(b):
        off = len(blobs)
        blobs.extend(b)
        return off

    descriptors, missing = [], []
    for dll, names in imports:
        entries = []
        for n in names:
            local, _, byord = n.partition("=")
            if local not in slots:
                missing.append(local); continue
            if byord.startswith("#"):
                # import by ordinal: the thunk value is (1<<63) | ordinal and
                # there is no hint/name entry at all
                entries.append((local, -int(byord[1:]), slots[local]))
            else:
                raw = struct.pack("<H", 0) + (byord or local).encode() + b"\0"
                if len(raw) % 2: raw += b"\0"
                entries.append((local, put(raw), slots[local]))
        if not entries: continue
        dll_off = put(dll.encode() + b"\0" + (b"\0" if len(dll) % 2 == 0 else b""))
        addrs = [a for _, _, a in entries]
        consecutive = all(addrs[i + 1] - addrs[i] == 8 for i in range(len(addrs) - 1))
        if consecutive:
            # one descriptor: the IAT is this run of GOT slots
            oft_off = put(b"".join(
                struct.pack("<Q", (1 << 63) | (-o) if o < 0 else o)
                for _, o, _ in entries) + struct.pack("<Q", 0))
            descriptors.append((oft_off, dll_off, addrs[0] - base,
                                [o for _, o, _ in entries]))
        else:
            # GOT slots are not contiguous: emit one descriptor per symbol
            for (n, hn_off, slot) in entries:
                oft_off = put(struct.pack("<QQ",
                    (1 << 63) | (-hn_off) if hn_off < 0 else hn_off, 0))
                descriptors.append((oft_off, dll_off, slot - base, [hn_off]))
    if missing:
        print("warning: no GOT slot for: " + ", ".join(missing), file=sys.stderr)

    desc_size = 20 * (len(descriptors) + 1)
    # hint/name pointers inside each OFT array become real RVAs now that the
    # size of the descriptor table is known
    for oft_off, dll_off, iat, hn_offs in descriptors:
        for k, hn in enumerate(hn_offs):
            if hn < 0:            # by ordinal: already a final value
                struct.pack_into("<Q", blobs, oft_off + 8 * k, (1 << 63) | (-hn))
            else:
                struct.pack_into("<Q", blobs, oft_off + 8 * k, idata_rva + desc_size + hn)
    idata = bytearray()
    for oft_off, dll_off, iat, _ in descriptors:
        idata.extend(struct.pack("<IIIII", idata_rva + desc_size + oft_off, 0, 0,
                                 idata_rva + desc_size + dll_off, iat))
    idata.extend(b"\0" * 20)                    # terminator
    idata.extend(blobs)
    import_dir = (idata_rva, desc_size) if descriptors else (0, 0)

    # ---- export thunks ----------------------------------------------------
    # MSVC-generated AXP64 code addresses everything absolutely and never sets
    # up gp, so it does not load pv (r27) with the callee's address before an
    # indirect call.  gcc-generated Alpha code, on the other hand, derives gp
    # from r27 in its prologue.  Every export therefore goes through a thunk
    # that recomputes r27 from the PC and then enters the real function.
    #
    #     br   $27, .+4        ; r27 = address of the next instruction
    #     ldah $27, hi($27)
    #     lda  $27, lo($27)    ; r27 = &target
    #     jmp  $31, ($27)
    THUNK_SIZE = 16
    thunk_rva = align_up(idata_rva + len(idata), peb.sa)
    thunks, thunk_of = bytearray(), {}
    def mem(op, ra, rb, d):            # memory-format encoding
        return (op << 26) | (ra << 21) | (rb << 16) | (d & 0xFFFF)

    def emit_thunk(target_value, label):
        """Append a pv-setup thunk jumping to target_value; return its VA."""
        here = base + thunk_rva + len(thunks)
        off = target_value - (here + 4)        # relative to the ldah, which
        lo = ((off & 0xFFFF) ^ 0x8000) - 0x8000            # br leaves in r27
        hi = (off - lo) >> 16
        assert -0x8000 <= hi <= 0x7FFF, f"{label}: out of reach for a 32-bit thunk"
        PV, ZERO = 27, 31
        for insn in (0x30 << 26 | PV << 21,            # br   $27, .+4
                     mem(0x09, PV, PV, hi),            # ldah $27, hi($27)
                     mem(0x08, PV, PV, lo),            # lda  $27, lo($27)
                     mem(0x1A, ZERO, PV, 0)):          # jmp  $31, ($27)
            thunks.extend(struct.pack("<I", insn))
        return here

    # parse EXPNAME[=symbol][:data]
    exports = {}
    for spec in args.export:
        is_data = spec.endswith(":data")
        if is_data: spec = spec[:-5]
        expname, _, local = spec.partition("=")
        exports[expname] = (local or expname, is_data)
    # parse ORD=symbol, or @file holding one per line (MFC42 style: no names)
    ord_exports = {}
    ord_data = set()
    def add_ord(spec):
        spec = spec.split("#")[0].strip()
        if not spec: return
        if spec.endswith(":data"):
            spec = spec[:-5]
            o, _, local = spec.partition("=")
            ord_data.add(int(o, 0))
            ord_exports[int(o, 0)] = local or None
            return
        o, _, local = spec.partition("=")
        ord_exports[int(o, 0)] = local or None
    for spec in args.export_ord:
        if spec.startswith("@"):
            with open(spec[1:]) as fh:
                for line in fh: add_ord(line)
        else:
            add_ord(spec)

    for n in sorted(exports):
        local, is_data = exports[n]
        sym = syms.get(local)
        if not sym:
            print(f"warning: export {n} ({local}) is not defined", file=sys.stderr)
            continue
        if is_data:
            continue                           # data exports need no thunk
        thunk_of[n] = emit_thunk(sym["value"], n)
    ord_thunk = {}
    for o in sorted(ord_exports):
        if o in ord_data:
            continue                          # data: export the address itself
        local = ord_exports[o]
        sym = syms.get(local) if local else None
        if not sym:
            if local:
                print(f"warning: ordinal {o} ({local}) is not defined", file=sys.stderr)
            continue
        ord_thunk[o] = emit_thunk(sym["value"], f"#{o}")

    # ---- export directory -------------------------------------------------
    edata_rva = align_up(thunk_rva + len(thunks), peb.sa) if thunks \
                else align_up(idata_rva + len(idata), peb.sa)
    edata = bytearray()
    export_dir = (0, 0)
    if exports or ord_exports:
        # ordinal -> RVA, covering fixed-ordinal exports and named ones
        ordmap = {}
        for o, local in ord_exports.items():
            if o in ord_thunk:
                ordmap[o] = ord_thunk[o] - base
            else:
                a = syms.get(local) if local else None
                ordmap[o] = (a["value"] - base) if a else 0
        names = sorted(exports)
        next_ord = (max(ordmap) + 1) if ordmap else 1
        name_ord = {}
        for n in names:
            if n in thunk_of:
                rva = thunk_of[n] - base
            else:
                a = syms.get(exports[n][0])
                rva = (a["value"] - base) if a else 0
            name_ord[n] = next_ord
            ordmap[next_ord] = rva
            next_ord += 1
        lo_ord, hi_ord = min(ordmap), max(ordmap)
        nfun = hi_ord - lo_ord + 1
        addr_off = 40
        name_ptr_off = addr_off + 4 * nfun
        ord_off = name_ptr_off + 4 * len(names)
        strs_off = ord_off + 2 * len(names)
        strs = bytearray()
        dllname_off = strs_off
        strs.extend(b"module.dll\0")
        name_rvas = []
        for n in names:
            name_rvas.append(edata_rva + strs_off + len(strs))
            strs.extend(n.encode() + b"\0")
        edata.extend(struct.pack("<IIHHIIIIIII", 0, 0, 0, 0,
                                 edata_rva + dllname_off, lo_ord, nfun, len(names),
                                 edata_rva + addr_off, edata_rva + name_ptr_off,
                                 edata_rva + ord_off))
        for i in range(nfun):                      # sparse address table
            edata.extend(struct.pack("<I", ordmap.get(lo_ord + i, 0)))
        for r in name_rvas:
            edata.extend(struct.pack("<I", r))
        for n in names:
            edata.extend(struct.pack("<H", name_ord[n] - lo_ord))
        edata.extend(strs)
        export_dir = (edata_rva, len(edata))

    # ---- assemble ---------------------------------------------------------
    for pename, g in groups.items():
        peb.add(pename, g["rva"], g["blob"], g["vsize"], g["ch"])
    if idata:
        peb.add(".idata", idata_rva, bytes(idata), len(idata), SEC_RDATA)
    if thunks:
        peb.add(".thunk", thunk_rva, bytes(thunks), len(thunks), SEC_CODE)
    if edata:
        peb.add(".edata", edata_rva, bytes(edata), len(edata), SEC_RDATA)

    entry_sym = args.entry
    entry_rva = (syms[entry_sym]["value"] - base) if entry_sym else (elf.e_entry - base)

    dirs = {}
    if export_dir[1]: dirs[0] = export_dir
    if import_dir[1]: dirs[1] = import_dir
    # IAT directory: the GOT region
    if got: dirs[12] = (got["addr"] - base, got["size"])

    pe = peb.build(entry_rva, args.dll, dirs, args.subsystem)
    open(args.out, "wb").write(pe)
    print(f"wrote {args.out}: base={base:#x} entry={entry_rva:#x} "
          f"sections={len(peb.sections)} gp={gp:#x} got_slots={len(slots)}")
    for n, a in sorted(slots.items()):
        print(f"   GOT slot {a:#x} -> {n}")

if __name__ == "__main__":
    main()
