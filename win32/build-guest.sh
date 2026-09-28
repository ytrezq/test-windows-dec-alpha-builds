#!/bin/sh
# Build the AXP64 (Windows/DEC Alpha) guest side: the thin Win32 layer and
# the demo program.  Everything produced here is DEC Alpha machine code in a
# PE32+ container; only winhost.exe underneath it is x86-64.
set -e
cd "$(dirname "$0")/.."
MK=toolchain/mkaxp64.sh
OUT=${OUT:-build/guest}
mkdir -p "$OUT"

python3 win32/genfwd.py >/dev/null

expand() { EX=""; while read -r e; do [ -n "$e" ] && EX="$EX --export $e"; done < "$1"; echo "$EX"; }
gates()  { grep -o "__${1}_[A-Za-z_0-9]*" "$2" | sort -u | tr '\n' ',' | sed 's/,$//'; }

# ---- MSVCRT: the CRT and the compiler's _Ots* helpers -------------------
$MK -o "$OUT/MSVCRT.dll" --dll --base 0x78000000 --entry DllMain \
    --import "axpwin:__sys_mem,__sys_write,__sys_debug,__sys_exit,__divl,__divlu,__divq,__divqu,__reml,__remq,__remqu" \
    $(expand win32/msvcrt.exports) win32/msvcrt.c >/dev/null
echo "MSVCRT.dll"

# ---- KERNEL32 ----------------------------------------------------------
$MK -o "$OUT/KERNEL32.dll" --dll --base 0x77e00000 --entry DllMain \
    --import "axpwin:__sys_mem,__sys_open,__sys_read,__sys_write,__sys_seek,__sys_close,__sys_fsize,__sys_debug,__sys_exit,__sys_ticks,__sys_time,__sys_cmdline,__sys_load,__sys_module_base,__sys_module_path,__sys_module_proc" \
    $(expand win32/kernel32.full.exports) win32/kernel32.c >/dev/null
echo "KERNEL32.dll"

# ---- USER32 / GDI32 ----------------------------------------------------
GU="__gu_RegisterClassA,__gu_RegisterClassExA,__gu_CreateWindowExA,__gu_ShowWindow,__gu_UpdateWindow,__gu_DestroyWindow,__gu_DefWindowProcA,__gu_GetMessageA,__gu_PeekMessageA,__gu_TranslateMessage,__gu_DispatchMessageA,__gu_PostQuitMessage,__gu_PostMessageA,__gu_SendMessageA,__gu_BeginPaint,__gu_EndPaint,__gu_GetClientRect,__gu_InvalidateRect,__gu_FillRect,__gu_LoadCursorA,__gu_LoadIconA,__gu_SetTimer,__gu_KillTimer,__gu_GetSystemMetrics,__gu_MessageBoxA,__gu_SetWindowTextA,__gu_MoveWindow,__gu_LoadMenuFromModule,__gu_wsprintfA,$(cat win32/user32x.gates)"
U_EXP="RegisterClassA RegisterClassExA CreateWindowExA CreateWindowA ShowWindow UpdateWindow DestroyWindow DefWindowProcA GetMessageA PeekMessageA TranslateMessage DispatchMessageA PostQuitMessage PostMessageA SendMessageA BeginPaint EndPaint GetClientRect InvalidateRect FillRect LoadCursorA LoadIconA SetTimer KillTimer GetSystemMetrics MessageBoxA SetWindowTextA MoveWindow LoadMenuA wsprintfA $(tr '\n' ' ' < win32/user32x.exports)"
UE=""; for e in $U_EXP; do UE="$UE --export $e"; done
$MK -o "$OUT/USER32.dll" --dll --base 0x77c00000 --entry DllMain \
    --import "winhost:$GU" $UE win32/user32.c win32/user32x_gen.c >/dev/null
echo "USER32.dll"

GD="__gd_CreateSolidBrush,__gd_DeleteObject,__gd_SetBkMode,__gd_SetTextColor,__gd_SetBkColor,__gd_TextOutA,__gd_Ellipse,__gd_Rectangle,__gd_MoveToEx,__gd_LineTo,__gd_SelectObject,__gd_CreatePen,__gd_GetStockObject,__gd_SetPixel,$(cat win32/gdi32x.gates)"
G_EXP="CreateSolidBrush DeleteObject SetBkMode SetTextColor SetBkColor TextOutA Ellipse Rectangle MoveToEx LineTo SelectObject CreatePen GetStockObject SetPixel $(tr '\n' ' ' < win32/gdi32x.exports)"
GE=""; for e in $G_EXP; do GE="$GE --export $e"; done
$MK -o "$OUT/GDI32.dll" --dll --base 0x77d00000 --entry DllMain \
    --import "winhost:$GD" $GE win32/gdi32.c win32/gdi32x_gen.c >/dev/null
echo "GDI32.dll"

# ---- the generated forwarding DLLs -------------------------------------
fwd() {
    low=$(echo "$1" | tr 'A-Z' 'a-z')
    $MK -o "$OUT/$1.dll" --dll --base "$2" --entry DllMain \
        --import "winhost:$(gates "$3" win32/${low}_gen.c)" \
        $(expand win32/${low}.exports) win32/${low}_gen.c >/dev/null
    echo "$1.dll"
}
fwd ADVAPI32 0x77a00000 adv
fwd SHELL32  0x7c800000 shl
fwd COMDLG32 0x76b00000 cdg
fwd COMCTL32 0x71700000 cc

# ---- the demo: a real window, drawn entirely by Alpha code -------------
$MK -o "$OUT/gui1.exe" --base 0x400000 --entry entry \
    --import "USER32.dll:RegisterClassA,CreateWindowExA,ShowWindow,UpdateWindow,DestroyWindow,DefWindowProcA,GetMessageA,TranslateMessage,DispatchMessageA,PostQuitMessage,BeginPaint,EndPaint,GetClientRect,LoadCursorA,SetTimer,FillRect" \
    --import "GDI32.dll:CreateSolidBrush,DeleteObject,SetBkMode,SetTextColor,TextOutA,Ellipse,MoveToEx,LineTo" \
    --import "KERNEL32.dll:OutputDebugStringA,ExitProcess" \
    win32/gui1.c >/dev/null
echo "gui1.exe"
echo "guest side in $OUT/"
