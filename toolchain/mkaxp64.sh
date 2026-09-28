#!/bin/sh
# mkaxp64 - build a Windows AXP64 (DEC Alpha 64-bit) PE from C sources.
#
#   mkaxp64.sh -o app.exe --base 0x400000 --entry entry \
#              --import "KERNEL32.dll:Foo,Bar" [--export Baz] file.c ...
#
# There is no Alpha-PE toolchain in existence (LLVM dropped its Alpha
# backend in 3.0; binutils has no alpha-pe target), so the route is:
#   C --gcc--> Alpha ELF --ld--> image at a fixed base --elf2pe--> AXP64 PE
set -e
HERE=$(dirname "$0")
OUT=a.exe; BASE=0x400000; ENTRY=entry; DLL=""; IMPORTS=""; EXPORTS=""; SRCS=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT=$2; shift 2;;
    --base) BASE=$2; shift 2;;
    --entry) ENTRY=$2; shift 2;;
    --dll) DLL=--dll; shift;;
    --import) IMPORTS="$IMPORTS --import $2"; shift 2;;
    --export) EXPORTS="$EXPORTS --export $2"; shift 2;;
    --export-file) while read -r e; do [ -n "$e" ] && EXPORTS="$EXPORTS --export $e"; done < "$2"; shift 2;;
    --export-ord) EXPORTS="$EXPORTS --export-ord $2"; shift 2;;
    *) SRCS="$SRCS $1"; shift;;
  esac
done
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
OBJS=""
for s in $SRCS; do
  o="$TMP/$(basename "$s" .c).o"
  alpha-linux-gnu-gcc -O2 -mcpu=ev6 -fno-pic -ffreestanding -fno-builtin \
      -fno-stack-protector -c -o "$o" "$s"
  OBJS="$OBJS $o"
done
# every imported symbol is defined as absolute 0 so that ld allocates a GOT
# slot for it; that slot becomes the PE import address table entry
DEFS=""
for spec in $(echo "$IMPORTS" | tr ' ' '\n' | grep ':' || true); do
  names=${spec#*:}
  for n in $(echo "$names" | tr ',' ' '); do DEFS="$DEFS --defsym ${n%%=*}=0"; done
done
TEXT=$(printf '0x%x' $(( BASE + 0x2000 )))
sed "s/@TEXT@/$TEXT/" "$HERE/axp64.ld.in" > "$TMP/link.ld"
alpha-linux-gnu-ld -T "$TMP/link.ld" --emit-relocs -o "$TMP/image.elf" $OBJS $DEFS 2>&1 \
  | grep -v 'RWX permissions' || true
python3 "$HERE/elf2pe.py" "$TMP/image.elf" "$OUT" $DLL --entry "$ENTRY" $IMPORTS $EXPORTS
