/* advapi32.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real advapi32. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern int __adv_RegOpenKeyA(long long a0, void * a1, void * a2);
int RegOpenKeyA(long long a0, void * a1, void * a2) { return __adv_RegOpenKeyA(a0, a1, a2); }
extern int __adv_RegOpenKeyExA(long long a0, void * a1, unsigned int a2, unsigned int a3, void * a4);
int RegOpenKeyExA(long long a0, void * a1, unsigned int a2, unsigned int a3, void * a4) { return __adv_RegOpenKeyExA(a0, a1, a2, a3, a4); }
extern int __adv_RegCloseKey(long long a0);
int RegCloseKey(long long a0) { return __adv_RegCloseKey(a0); }
extern int __adv_RegQueryValueA(long long a0, void * a1, void * a2, void * a3);
int RegQueryValueA(long long a0, void * a1, void * a2, void * a3) { return __adv_RegQueryValueA(a0, a1, a2, a3); }
extern int __adv_RegQueryValueExA(long long a0, void * a1, void * a2, void * a3, void * a4, void * a5);
int RegQueryValueExA(long long a0, void * a1, void * a2, void * a3, void * a4, void * a5) { return __adv_RegQueryValueExA(a0, a1, a2, a3, a4, a5); }
extern int __adv_RegSetValueA(long long a0, void * a1, unsigned int a2, void * a3, int a4);
int RegSetValueA(long long a0, void * a1, unsigned int a2, void * a3, int a4) { return __adv_RegSetValueA(a0, a1, a2, a3, a4); }
extern int __adv_RegEnumKeyA(long long a0, unsigned int a1, void * a2, unsigned int a3);
int RegEnumKeyA(long long a0, unsigned int a1, void * a2, unsigned int a3) { return __adv_RegEnumKeyA(a0, a1, a2, a3); }
extern int __adv_RegEnumValueA(long long a0, unsigned int a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7);
int RegEnumValueA(long long a0, unsigned int a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7) { return __adv_RegEnumValueA(a0, a1, a2, a3, a4, a5, a6, a7); }
extern int __adv_RegDeleteKeyA(long long a0, void * a1);
int RegDeleteKeyA(long long a0, void * a1) { return __adv_RegDeleteKeyA(a0, a1); }
extern int __adv_GetUserNameA(void * a0, void * a1);
int GetUserNameA(void * a0, void * a1) { return __adv_GetUserNameA(a0, a1); }

int DllMain(void *i, unsigned r, void *v) { return 1; }
