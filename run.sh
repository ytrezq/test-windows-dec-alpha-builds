#!/bin/sh
# Run an AXP64 program under the translator.  Wine is stock: winhost.exe is
# an ordinary x86-64 Windows binary, everything above it is DEC Alpha.
#   ./run.sh                     the bundled demo
#   ./run.sh path/to/other.exe   anything else built for Windows AXP64
set -e
cd "$(dirname "$0")"
G=build/guest
TARGET=${1:-$G/gui1.exe}
[ -f build/winhost.exe ] || { echo "run 'make' first"; exit 1; }
if [ -z "$DISPLAY" ]; then
    D=:$((70 + $$ % 20))
    Xvfb $D -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 &
    XP=$!; trap 'kill $XP 2>/dev/null' EXIT
    for i in $(seq 40); do [ -e /tmp/.X11-unix/X${D#:} ] && break; sleep 0.1; done
    export DISPLAY=$D
fi
exec wine build/winhost.exe -k \
    "$TARGET" "$G/KERNEL32.dll" "$G/MSVCRT.dll" "$G/USER32.dll" "$G/GDI32.dll" \
    "$G/ADVAPI32.dll" "$G/SHELL32.dll" "$G/COMDLG32.dll" "$G/COMCTL32.dll"
