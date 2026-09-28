import sys, struct, tempfile, importlib.util, os
spec = importlib.util.spec_from_file_location("dt", os.path.join(os.path.dirname(os.path.abspath(__file__)),"difftest.py"))
dt = importlib.util.module_from_spec(spec); spec.loader.exec_module(dt)
insns = [l for l in sys.argv[1].split(";") if l.strip()]
insns = ["\t"+i.strip() for i in insns]
st = [0]*65
st[20] = dt.DATA_BASE; st[21] = dt.DATA_BASE+0x800; st[30] = dt.DATA_BASE+0x400
st[64] = (2<<58)|(1<<61)|(1<<60)|(1<<51)|(1<<50)|(1<<49)
for kv in sys.argv[2:]:
    k,v = kv.split("="); 
    if k.startswith("f"): st[32+int(k[1:])] = int(v,0)
    else: st[int(k[1:])] = int(v,0)
wd = tempfile.mkdtemp(prefix="one-")
res, err = dt.build_and_run(wd, insns, st)
if err: print("ERR:", err); sys.exit(1)
ref, emu, se = res
rs = struct.unpack('<65Q', ref[:520]); es = struct.unpack('<65Q', emu[:520])
print("insns:", insns)
for i in range(32):
    if i in (29,31): continue
    if rs[i]!=es[i]: print(f"  r{i}: ref={rs[i]:#018x} emu={es[i]:#018x}")
for i in range(31):
    if rs[32+i]!=es[32+i]: print(f"  f{i}: ref={rs[32+i]:#018x} emu={es[32+i]:#018x}")
print("  (no diffs)" if all(rs[i]==es[i] for i in list(range(29))+[30]+[32+j for j in range(31)]) else "")
if se.strip(): print("emu stderr:", se.strip())
