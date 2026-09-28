/* gdi32x.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real gdi32x. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern long long __gd2_CreateFontIndirectA(void * a0);
long long CreateFontIndirectA(void * a0) { return __gd2_CreateFontIndirectA(a0); }
extern int __gd2_ExtTextOutA(long long a0, int a1, int a2, unsigned int a3, void * a4, void * a5, unsigned int a6, void * a7);
int ExtTextOutA(long long a0, int a1, int a2, unsigned int a3, void * a4, void * a5, unsigned int a6, void * a7) { return __gd2_ExtTextOutA(a0, a1, a2, a3, a4, a5, a6, a7); }
extern int __gd2_GetCharWidthA(long long a0, unsigned int a1, unsigned int a2, void * a3);
int GetCharWidthA(long long a0, unsigned int a1, unsigned int a2, void * a3) { return __gd2_GetCharWidthA(a0, a1, a2, a3); }
extern int __gd2_GetObjectA(long long a0, int a1, void * a2);
int GetObjectA(long long a0, int a1, void * a2) { return __gd2_GetObjectA(a0, a1, a2); }
extern unsigned int __gd2_GetTextAlign(long long a0);
unsigned int GetTextAlign(long long a0) { return __gd2_GetTextAlign(a0); }
extern int __gd2_GetTextExtentPoint32A(long long a0, void * a1, int a2, void * a3);
int GetTextExtentPoint32A(long long a0, void * a1, int a2, void * a3) { return __gd2_GetTextExtentPoint32A(a0, a1, a2, a3); }
extern int __gd2_GetTextExtentPointA(long long a0, void * a1, int a2, void * a3);
int GetTextExtentPointA(long long a0, void * a1, int a2, void * a3) { return __gd2_GetTextExtentPointA(a0, a1, a2, a3); }
extern unsigned int __gd2_SetTextAlign(long long a0, unsigned int a1);
unsigned int SetTextAlign(long long a0, unsigned int a1) { return __gd2_SetTextAlign(a0, a1); }

