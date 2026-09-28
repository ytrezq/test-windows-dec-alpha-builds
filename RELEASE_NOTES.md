# v0.1.0 — AXP64 runtime, prebuilt

Prebuilt binaries for running **Windows AXP64** executables — 64-bit DEC
Alpha, PE32+ machine type `0x0284` — on x86-64 Linux.

## Contents

| | |
|---|---|
| `axpemu` | the standalone Alpha → x86-64 JIT (x86-64 Linux ELF) |
| `winhost.exe` | the Wine-hosted loader: PE loading, the PALcode call gate, the NX-fault return path, and the native side of the Win32 layer. The only native binary in the archive. |
| `guest/*.dll` | the Win32 layer itself, **compiled to DEC Alpha** — `KERNEL32`, `USER32`, `GDI32`, `MSVCRT`, `ADVAPI32`, `SHELL32`, `COMDLG32`, `COMCTL32` |
| `guest/gui1.exe` | an AXP64 test application, built from source in this repository |

## Running

```sh
unzip axp64-runtime-prebuilt.zip && cd axp64-runtime-prebuilt
wine winhost.exe -k guest/gui1.exe \
    guest/KERNEL32.dll guest/MSVCRT.dll guest/USER32.dll guest/GDI32.dll \
    guest/ADVAPI32.dll guest/SHELL32.dll guest/COMDLG32.dll guest/COMCTL32.dll
```

A window appears, drawn entirely by DEC Alpha code. `RUN.txt` has the rest.
Wine is used **unmodified**: the guest is mapped read-write non-executable at
its true addresses, and every transition is either a PALcode gate or a
trapped NX fault.

To run a different AXP64 program, put its path in place of `guest/gui1.exe`.

## Provenance

The Alpha modules in `guest/` are original code written against the published
Win32 API — the same clean-room position Wine occupies, and the reason Wine
ships in distributions at all. They carry this repository's licence and are
meant to be redistributed in binary form.

This project is the AXP64 half of that idea: the same API reimplemented, for
an architecture Wine has no port for. (The amd64 side of the comparison in
`docs/` needed nothing compiled — stock `apt install wine` covers it.)

No Microsoft binary is included. `MFC42`, whose provenance is different and
is stated separately, lives in
[its own repository](https://github.com/ytrezq/dec-alpha-mfc42-partial-reverse-engineering).

## On the calling convention

These DLLs come from stock `alpha-linux-gnu` GCC, which targets the SysV
Alpha ABI — not Microsoft's Alpha calling standard. Rewrapping ELF as PE32+
does not change that, so the converter emits a procedure-value thunk per
export. What the two conventions share, what they do not, and what is still
missing (`.pdata`, hence no SEH) is measured rather than asserted in
[ABI.md](https://github.com/ytrezq/dec-alpha-cross-binutils/blob/main/ABI.md).

## Assets

* `axp64-runtime-prebuilt.zip` — the archive described above
