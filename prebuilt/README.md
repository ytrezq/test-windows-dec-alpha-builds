# Prebuilt runtime

`axp64-runtime-prebuilt.zip` is the compiled output of this repository, so
the AXP64 runtime can be tried without a cross toolchain installed.

```sh
unzip axp64-runtime-prebuilt.zip && cd axp64-runtime-prebuilt
cat RUN.txt
./run.sh
```

| | |
|---|---|
| `axpemu` | the standalone Alpha → x86-64 JIT (x86-64 Linux ELF) |
| `winhost.exe` | the Wine-hosted loader: PE loading, the PALcode call gate, the NX-fault return path, the native side of the Win32 layer |
| `guest/*.dll` | the Win32 layer, compiled to Alpha |
| `guest/gui1.exe` | an AXP64 test application, built from source here |

Needs `wine` and, for the windowed test, `Xvfb`. Wine is used unmodified.

No third-party binaries are redistributed. To run a real AXP64 application
you supply your own copy.
