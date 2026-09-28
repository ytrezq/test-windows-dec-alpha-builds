#!/bin/sh
set -e
cd "$(dirname "$0")/.."
MK=./mkaxp64.sh

GU="__gu_RegisterClassA,__gu_RegisterClassExA,__gu_CreateWindowExA,__gu_ShowWindow,__gu_UpdateWindow,__gu_DestroyWindow,__gu_DefWindowProcA,__gu_GetMessageA,__gu_PeekMessageA,__gu_TranslateMessage,__gu_DispatchMessageA,__gu_PostQuitMessage,__gu_PostMessageA,__gu_SendMessageA,__gu_BeginPaint,__gu_EndPaint,__gu_GetClientRect,__gu_InvalidateRect,__gu_FillRect,__gu_LoadCursorA,__gu_LoadIconA,__gu_SetTimer,__gu_KillTimer,__gu_GetSystemMetrics,__gu_MessageBoxA,__gu_SetWindowTextA,__gu_MoveWindow"
U_EXP="RegisterClassA RegisterClassExA CreateWindowExA CreateWindowA ShowWindow UpdateWindow DestroyWindow DefWindowProcA GetMessageA PeekMessageA TranslateMessage DispatchMessageA PostQuitMessage PostMessageA SendMessageA BeginPaint EndPaint GetClientRect InvalidateRect FillRect LoadCursorA LoadIconA SetTimer KillTimer GetSystemMetrics MessageBoxA SetWindowTextA MoveWindow"
UE=""; for e in $U_EXP; do UE="$UE --export $e"; done
GU="$GU,__gu_LoadMenuFromModule,__gu_wsprintfA,$(cat win32/user32x.gates)"
U_EXP="$U_EXP LoadMenuA wsprintfA $(tr '\n' ' ' < win32/user32x.exports)"
UE=""; for e in $U_EXP; do UE="$UE --export $e"; done
$MK -o win32/USER32.dll --dll --base 0x77c00000 --entry DllMain \
    --import "winhost:$GU" $UE win32/user32.c win32/user32x_gen.c
echo "USER32 built"

GD="__gd_CreateSolidBrush,__gd_DeleteObject,__gd_SetBkMode,__gd_SetTextColor,__gd_SetBkColor,__gd_TextOutA,__gd_Ellipse,__gd_Rectangle,__gd_MoveToEx,__gd_LineTo,__gd_SelectObject,__gd_CreatePen,__gd_GetStockObject,__gd_SetPixel"
G_EXP="CreateSolidBrush DeleteObject SetBkMode SetTextColor SetBkColor TextOutA Ellipse Rectangle MoveToEx LineTo SelectObject CreatePen GetStockObject SetPixel"
GE=""; for e in $G_EXP; do GE="$GE --export $e"; done
GD="$GD,$(cat win32/gdi32x.gates)"
G_EXP="$G_EXP $(tr '\n' ' ' < win32/gdi32x.exports)"
GE=""; for e in $G_EXP; do GE="$GE --export $e"; done
$MK -o win32/GDI32.dll --dll --base 0x77d00000 --entry DllMain \
    --import "winhost:$GD" $GE win32/gdi32.c win32/gdi32x_gen.c
echo "GDI32 built"

$MK -o win32/gui1.exe --base 0x400000 --entry entry \
    --import "USER32.dll:RegisterClassA,CreateWindowExA,ShowWindow,UpdateWindow,DestroyWindow,DefWindowProcA,GetMessageA,TranslateMessage,DispatchMessageA,PostQuitMessage,BeginPaint,EndPaint,GetClientRect,LoadCursorA,SetTimer,FillRect" \
    --import "GDI32.dll:CreateSolidBrush,DeleteObject,SetBkMode,SetTextColor,TextOutA,Ellipse,MoveToEx,LineTo" \
    --import "KERNEL32.dll:OutputDebugStringA,ExitProcess" \
    win32/gui1.c
echo "gui1 built"
