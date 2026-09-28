/* comctl32.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real comctl32. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern int __cc_ImageList_Draw(long long a0, int a1, long long a2, int a3, int a4, unsigned int a5);
int ImageList_Draw(long long a0, int a1, long long a2, int a3, int a4, unsigned int a5) { return __cc_ImageList_Draw(a0, a1, a2, a3, a4, a5); }
extern void __cc_InitCommonControls(void);
void InitCommonControls(void) { __cc_InitCommonControls(); }

int DllMain(void *i, unsigned r, void *v) { return 1; }
