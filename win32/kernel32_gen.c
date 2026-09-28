/* kernel32.dll for Windows AXP64 — generated thin stubs.
 * Each export runs as Alpha code and crosses one gate to the host,
 * which calls Wine's real kernel32. */
typedef unsigned int UINT; typedef unsigned int DWORD;
typedef int BOOL; typedef long long LL; typedef void *PV;
#define NULL ((void*)0)

extern long long __k32_FindFirstFileA(void * a0, void * a1);
long long FindFirstFileA(void * a0, void * a1) { return __k32_FindFirstFileA(a0, a1); }
extern int __k32_FindNextFileA(long long a0, void * a1);
int FindNextFileA(long long a0, void * a1) { return __k32_FindNextFileA(a0, a1); }
extern int __k32_FindClose(long long a0);
int FindClose(long long a0) { return __k32_FindClose(a0); }
extern unsigned int __k32_GetFullPathNameA(void * a0, unsigned int a1, void * a2, void * a3);
unsigned int GetFullPathNameA(void * a0, unsigned int a1, void * a2, void * a3) { return __k32_GetFullPathNameA(a0, a1, a2, a3); }
extern unsigned int __k32_GetFileAttributesA(void * a0);
unsigned int GetFileAttributesA(void * a0) { return __k32_GetFileAttributesA(a0); }
extern long long __k32_CreateFileA(void * a0, unsigned int a1, unsigned int a2, void * a3, unsigned int a4, unsigned int a5, long long a6);
long long CreateFileA(void * a0, unsigned int a1, unsigned int a2, void * a3, unsigned int a4, unsigned int a5, long long a6) { return __k32_CreateFileA(a0, a1, a2, a3, a4, a5, a6); }
extern int __k32_ReadFile(long long a0, void * a1, unsigned int a2, void * a3, void * a4);
int ReadFile(long long a0, void * a1, unsigned int a2, void * a3, void * a4) { return __k32_ReadFile(a0, a1, a2, a3, a4); }
extern unsigned int __k32_SetFilePointer(long long a0, int a1, void * a2, unsigned int a3);
unsigned int SetFilePointer(long long a0, int a1, void * a2, unsigned int a3) { return __k32_SetFilePointer(a0, a1, a2, a3); }
extern unsigned int __k32_GetFileSize(long long a0, void * a1);
unsigned int GetFileSize(long long a0, void * a1) { return __k32_GetFileSize(a0, a1); }
extern int __k32_CloseHandle(long long a0);
int CloseHandle(long long a0) { return __k32_CloseHandle(a0); }
extern long long __k32_CreateFileMappingA(long long a0, void * a1, unsigned int a2, unsigned int a3, unsigned int a4, void * a5);
long long CreateFileMappingA(long long a0, void * a1, unsigned int a2, unsigned int a3, unsigned int a4, void * a5) { return __k32_CreateFileMappingA(a0, a1, a2, a3, a4, a5); }
extern void * __k32_MapViewOfFile(long long a0, unsigned int a1, unsigned int a2, unsigned int a3, unsigned int a4);
void * MapViewOfFile(long long a0, unsigned int a1, unsigned int a2, unsigned int a3, unsigned int a4) { return __k32_MapViewOfFile(a0, a1, a2, a3, a4); }
extern int __k32_UnmapViewOfFile(void * a0);
int UnmapViewOfFile(void * a0) { return __k32_UnmapViewOfFile(a0); }
extern int __k32_GetFileInformationByHandle(long long a0, void * a1);
int GetFileInformationByHandle(long long a0, void * a1) { return __k32_GetFileInformationByHandle(a0, a1); }
extern unsigned int __k32_GetFileType(long long a0);
unsigned int GetFileType(long long a0) { return __k32_GetFileType(a0); }
extern int __k32_DeleteFileA(void * a0);
int DeleteFileA(void * a0) { return __k32_DeleteFileA(a0); }
extern unsigned int __k32_GetTempPathA(unsigned int a0, void * a1);
unsigned int GetTempPathA(unsigned int a0, void * a1) { return __k32_GetTempPathA(a0, a1); }
extern unsigned int __k32_GetShortPathNameA(void * a0, void * a1, unsigned int a2);
unsigned int GetShortPathNameA(void * a0, void * a1, unsigned int a2) { return __k32_GetShortPathNameA(a0, a1, a2); }
extern unsigned int __k32_GetWindowsDirectoryA(void * a0, unsigned int a1);
unsigned int GetWindowsDirectoryA(void * a0, unsigned int a1) { return __k32_GetWindowsDirectoryA(a0, a1); }
extern unsigned int __k32_GetSystemDirectoryA(void * a0, unsigned int a1);
unsigned int GetSystemDirectoryA(void * a0, unsigned int a1) { return __k32_GetSystemDirectoryA(a0, a1); }
extern unsigned int __k32_ExpandEnvironmentStringsA(void * a0, void * a1, unsigned int a2);
unsigned int ExpandEnvironmentStringsA(void * a0, void * a1, unsigned int a2) { return __k32_ExpandEnvironmentStringsA(a0, a1, a2); }
extern unsigned int __k32_GetDriveTypeA(void * a0);
unsigned int GetDriveTypeA(void * a0) { return __k32_GetDriveTypeA(a0); }
extern unsigned int __k32_GetLogicalDrives(void);
unsigned int GetLogicalDrives(void) { return __k32_GetLogicalDrives(); }
extern long long __k32_GlobalAlloc(unsigned int a0, unsigned int a1);
long long GlobalAlloc(unsigned int a0, unsigned int a1) { return __k32_GlobalAlloc(a0, a1); }
extern void * __k32_GlobalLock(long long a0);
void * GlobalLock(long long a0) { return __k32_GlobalLock(a0); }
extern int __k32_GlobalUnlock(long long a0);
int GlobalUnlock(long long a0) { return __k32_GlobalUnlock(a0); }
extern long long __k32_LocalFree(long long a0);
long long LocalFree(long long a0) { return __k32_LocalFree(a0); }
extern void __k32_GetSystemTimeAsFileTime(void * a0);
void GetSystemTimeAsFileTime(void * a0) { __k32_GetSystemTimeAsFileTime(a0); }
extern int __k32_FileTimeToLocalFileTime(void * a0, void * a1);
int FileTimeToLocalFileTime(void * a0, void * a1) { return __k32_FileTimeToLocalFileTime(a0, a1); }
extern int __k32_FileTimeToSystemTime(void * a0, void * a1);
int FileTimeToSystemTime(void * a0, void * a1) { return __k32_FileTimeToSystemTime(a0, a1); }
extern int __k32_CompareFileTime(void * a0, void * a1);
int CompareFileTime(void * a0, void * a1) { return __k32_CompareFileTime(a0, a1); }
extern int __k32_GetDateFormatA(unsigned int a0, unsigned int a1, void * a2, void * a3, void * a4, int a5);
int GetDateFormatA(unsigned int a0, unsigned int a1, void * a2, void * a3, void * a4, int a5) { return __k32_GetDateFormatA(a0, a1, a2, a3, a4, a5); }
extern int __k32_GetTimeFormatA(unsigned int a0, unsigned int a1, void * a2, void * a3, void * a4, int a5);
int GetTimeFormatA(unsigned int a0, unsigned int a1, void * a2, void * a3, void * a4, int a5) { return __k32_GetTimeFormatA(a0, a1, a2, a3, a4, a5); }
extern unsigned int __k32_FormatMessageA(unsigned int a0, void * a1, unsigned int a2, unsigned int a3, void * a4, unsigned int a5, void * a6);
unsigned int FormatMessageA(unsigned int a0, void * a1, unsigned int a2, unsigned int a3, void * a4, unsigned int a5, void * a6) { return __k32_FormatMessageA(a0, a1, a2, a3, a4, a5, a6); }
extern int __k32_GetLocaleInfoA(unsigned int a0, unsigned int a1, void * a2, int a3);
int GetLocaleInfoA(unsigned int a0, unsigned int a1, void * a2, int a3) { return __k32_GetLocaleInfoA(a0, a1, a2, a3); }
extern void __k32_GlobalMemoryStatus(void * a0);
void GlobalMemoryStatus(void * a0) { __k32_GlobalMemoryStatus(a0); }
extern int __k32_GetComputerNameA(void * a0, void * a1);
int GetComputerNameA(void * a0, void * a1) { return __k32_GetComputerNameA(a0, a1); }

int DllMain(void *i, unsigned r, void *v) { return 1; }
