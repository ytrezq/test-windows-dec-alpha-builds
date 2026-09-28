#!/bin/sh
set -e
cd "$(dirname "$0")/.."
python3 win32/genfwd.py >/dev/null
build() {  # name base prefix gatelist
  DLL=$1; BASE=$2; PFX=$3
  EXP=""; while read -r e; do [ -n "$e" ] && EXP="$EXP --export $e"; done < "win32/$(echo $DLL|tr A-Z a-z).exports"
  GATES=$(grep -o "__${PFX}_[A-Za-z_0-9]*" "win32/$(echo $DLL|tr A-Z a-z)_gen.c" | sort -u | tr '\n' ',' | sed 's/,$//')
  ./mkaxp64.sh -o "win32/$DLL.dll" --dll --base $BASE --entry DllMain \
      --import "winhost:$GATES" $EXP "win32/$(echo $DLL|tr A-Z a-z)_gen.c" >/dev/null
  echo "$DLL.dll built"
}
build ADVAPI32 0x77a00000 adv
build SHELL32  0x7c800000 shl
build COMDLG32 0x76b00000 cdg
build COMCTL32 0x71700000 cc
