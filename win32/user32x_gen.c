/* user32x.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real user32x. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern int __gu2_CloseClipboard(void);
int CloseClipboard(void) { return __gu2_CloseClipboard(); }
extern int __gu2_CopyRect(void * a0, void * a1);
int CopyRect(void * a0, void * a1) { return __gu2_CopyRect(a0, a1); }
extern int __gu2_DrawFocusRect(long long a0, void * a1);
int DrawFocusRect(long long a0, void * a1) { return __gu2_DrawFocusRect(a0, a1); }
extern int __gu2_EmptyClipboard(void);
int EmptyClipboard(void) { return __gu2_EmptyClipboard(); }
extern int __gu2_EnableMenuItem(long long a0, unsigned int a1, unsigned int a2);
int EnableMenuItem(long long a0, unsigned int a1, unsigned int a2) { return __gu2_EnableMenuItem(a0, a1, a2); }
extern int __gu2_EnableWindow(long long a0, int a1);
int EnableWindow(long long a0, int a1) { return __gu2_EnableWindow(a0, a1); }
extern long long __gu2_GetDC(long long a0);
long long GetDC(long long a0) { return __gu2_GetDC(a0); }
extern long long __gu2_GetDlgItem(long long a0, int a1);
long long GetDlgItem(long long a0, int a1) { return __gu2_GetDlgItem(a0, a1); }
extern long long __gu2_GetFocus(void);
long long GetFocus(void) { return __gu2_GetFocus(); }
extern unsigned int __gu2_GetMessagePos(void);
unsigned int GetMessagePos(void) { return __gu2_GetMessagePos(); }
extern int __gu2_GetMessageTime(void);
int GetMessageTime(void) { return __gu2_GetMessageTime(); }
extern long long __gu2_GetParent(long long a0);
long long GetParent(long long a0) { return __gu2_GetParent(a0); }
extern long long __gu2_GetSubMenu(long long a0, int a1);
long long GetSubMenu(long long a0, int a1) { return __gu2_GetSubMenu(a0, a1); }
extern unsigned int __gu2_GetSysColor(int a0);
unsigned int GetSysColor(int a0) { return __gu2_GetSysColor(a0); }
extern int __gu2_GetWindowRect(long long a0, void * a1);
int GetWindowRect(long long a0, void * a1) { return __gu2_GetWindowRect(a0, a1); }
extern int __gu2_GetWindowTextA(long long a0, void * a1, int a2);
int GetWindowTextA(long long a0, void * a1, int a2) { return __gu2_GetWindowTextA(a0, a1, a2); }
extern int __gu2_GetWindowTextLengthA(long long a0);
int GetWindowTextLengthA(long long a0) { return __gu2_GetWindowTextLengthA(a0); }
extern int __gu2_IsIconic(long long a0);
int IsIconic(long long a0) { return __gu2_IsIconic(a0); }
extern int __gu2_IsWindow(long long a0);
int IsWindow(long long a0) { return __gu2_IsWindow(a0); }
extern int __gu2_IsWindowEnabled(long long a0);
int IsWindowEnabled(long long a0) { return __gu2_IsWindowEnabled(a0); }
extern int __gu2_IsZoomed(long long a0);
int IsZoomed(long long a0) { return __gu2_IsZoomed(a0); }
extern int __gu2_MessageBeep(unsigned int a0);
int MessageBeep(unsigned int a0) { return __gu2_MessageBeep(a0); }
extern int __gu2_OpenClipboard(long long a0);
int OpenClipboard(long long a0) { return __gu2_OpenClipboard(a0); }
extern int __gu2_ReleaseDC(long long a0, long long a1);
int ReleaseDC(long long a0, long long a1) { return __gu2_ReleaseDC(a0, a1); }
extern int __gu2_RemoveMenu(long long a0, unsigned int a1, unsigned int a2);
int RemoveMenu(long long a0, unsigned int a1, unsigned int a2) { return __gu2_RemoveMenu(a0, a1, a2); }
extern int __gu2_ScreenToClient(long long a0, void * a1);
int ScreenToClient(long long a0, void * a1) { return __gu2_ScreenToClient(a0, a1); }
extern long long __gu2_SetClipboardData(unsigned int a0, long long a1);
long long SetClipboardData(unsigned int a0, long long a1) { return __gu2_SetClipboardData(a0, a1); }
extern long long __gu2_SetFocus(long long a0);
long long SetFocus(long long a0) { return __gu2_SetFocus(a0); }
extern int __gu2_DrawMenuBar(long long a0);
int DrawMenuBar(long long a0) { return __gu2_DrawMenuBar(a0); }
extern int __gu2_SetMenu(long long a0, long long a1);
int SetMenu(long long a0, long long a1) { return __gu2_SetMenu(a0, a1); }
extern long long __gu2_GetMenu(long long a0);
long long GetMenu(long long a0) { return __gu2_GetMenu(a0); }
extern int __gu2_WinHelpA(long long a0, void * a1, unsigned int a2, long long a3);
int WinHelpA(long long a0, void * a1, unsigned int a2, long long a3) { return __gu2_WinHelpA(a0, a1, a2, a3); }

