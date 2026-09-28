/* shell32.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real shell32. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern long long __shl_ShellExecuteA(long long a0, void * a1, void * a2, void * a3, void * a4, int a5);
long long ShellExecuteA(long long a0, void * a1, void * a2, void * a3, void * a4, int a5) { return __shl_ShellExecuteA(a0, a1, a2, a3, a4, a5); }
extern int __shl_ShellExecuteExA(void * a0);
int ShellExecuteExA(void * a0) { return __shl_ShellExecuteExA(a0); }
extern int __shl_SHGetPathFromIDListA(void * a0, void * a1);
int SHGetPathFromIDListA(void * a0, void * a1) { return __shl_SHGetPathFromIDListA(a0, a1); }
extern long long __shl_SHBrowseForFolderA(void * a0);
long long SHBrowseForFolderA(void * a0) { return __shl_SHBrowseForFolderA(a0); }
extern int __shl_SHGetMalloc(void * a0);
int SHGetMalloc(void * a0) { return __shl_SHGetMalloc(a0); }

int DllMain(void *i, unsigned r, void *v) { return 1; }
