/* comdlg32.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real comdlg32. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern int __cdg_GetOpenFileNameA(void * a0);
int GetOpenFileNameA(void * a0) { return __cdg_GetOpenFileNameA(a0); }
extern int __cdg_GetSaveFileNameA(void * a0);
int GetSaveFileNameA(void * a0) { return __cdg_GetSaveFileNameA(a0); }
extern unsigned int __cdg_CommDlgExtendedError(void);
unsigned int CommDlgExtendedError(void) { return __cdg_CommDlgExtendedError(); }

int DllMain(void *i, unsigned r, void *v) { return 1; }
