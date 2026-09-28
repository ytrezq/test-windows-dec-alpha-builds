/* kernel32.dll for Windows AXP64 — compiled to DEC Alpha code.
 *
 * This is guest-architecture code, exactly like a Wine PE-side DLL: the
 * Win32 semantics live here in Alpha machine code, and only a handful of
 * primitives cross into the host (the __sys_* imports, our unixlib).
 */
typedef unsigned char      BYTE;
typedef unsigned short     WORD;
typedef unsigned int       DWORD;
typedef int                BOOL;
typedef unsigned long      ULONG_PTR;
typedef void              *HANDLE;
typedef void              *LPVOID;
typedef const char        *LPCSTR;
typedef char              *LPSTR;
typedef const unsigned short *LPCWSTR;

#define NULL ((void*)0)
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)

/* ---- the unixlib boundary: the only native calls in this module ------- */
extern long  __sys_write(int fd, const void *buf, unsigned long len);
extern long  __sys_read(int fd, void *buf, unsigned long len);
extern long  __sys_open(const char *path, int flags);
extern long  __sys_close(int fd);
extern long  __sys_seek(int fd, long off, int whence);
extern long  __sys_fsize(int fd);
extern void *__sys_mem(unsigned long size);
extern long  __sys_ticks(void);
extern long  __sys_time(void);
extern void  __sys_exit(int code);
extern void *__sys_module_base(const char *name);
extern long  __sys_module_path(void *base, char *buf, unsigned long len);
extern void *__sys_module_proc(void *base, const char *name, unsigned long ordinal);
extern void  __sys_debug(const char *s);
extern void *__sys_load(const char *path);
extern long  __sys_cmdline(char *buf, unsigned long len);

/* ---- tiny local runtime (no CRT available) --------------------------- */
static unsigned long s_strlen(const char *s) { const char *p = s; while (*p) p++; return (unsigned long)(p - s); }
static void s_memset(void *d, int c, unsigned long n) { BYTE *p = d; while (n--) *p++ = (BYTE)c; }
static void s_memcpy(void *d, const void *s, unsigned long n) { BYTE *p = d; const BYTE *q = s; while (n--) *p++ = *q++; }
static int  s_stricmp(const char *a, const char *b)
{
    for (;; a++, b++) {
        int x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y || !x) return x - y;
    }
}
static unsigned long s_strlcpy(char *d, const char *s, unsigned long n)
{
    unsigned long l = s_strlen(s);
    if (n) { unsigned long c = l < n - 1 ? l : n - 1; s_memcpy(d, s, c); d[c] = 0; }
    return l;
}

/* ---- per-process state ------------------------------------------------ */
static DWORD  last_error;
static char   cmdline[512];
static int    cmdline_init;

/* a simple bump heap carved out of host memory, enough for a loader run */
#define HEAPBLK 0x100000
static BYTE  *heap_cur, *heap_end;
static void *heap_alloc(unsigned long n)
{
    n = (n + 15) & ~15UL;
    if (heap_cur + n > heap_end) {
        unsigned long want = n > HEAPBLK ? n : HEAPBLK;
        heap_cur = __sys_mem(want);
        if (!heap_cur) return NULL;
        heap_end = heap_cur + want;
    }
    void *p = heap_cur;
    heap_cur += n;
    return p;
}

/* ---- error handling --------------------------------------------------- */
DWORD GetLastError(void) { return last_error; }
void  SetLastError(DWORD e) { last_error = e; }

/* ---- memory ----------------------------------------------------------- */
void  RtlZeroMemory(void *d, unsigned long n) { s_memset(d, 0, n); }
void  RtlCopyMemory(void *d, const void *s, unsigned long n) { s_memcpy(d, s, n); }
void  RtlFillMemory(void *d, unsigned long n, int c) { s_memset(d, c, n); }

#define GMEM_ZEROINIT 0x0040
HANDLE GlobalAlloc(unsigned flags, unsigned long n)
{
    void *p = heap_alloc(n ? n : 1);
    if (p && (flags & GMEM_ZEROINIT)) s_memset(p, 0, n);
    return p;
}
LPVOID GlobalLock(HANDLE h)   { return h; }
BOOL   GlobalUnlock(HANDLE h) { return TRUE; }
HANDLE GlobalFree(HANDLE h)   { return NULL; }
unsigned long GlobalSize(HANDLE h) { return 0; }
HANDLE LocalFree(HANDLE h)    { return NULL; }
HANDLE LocalAlloc(unsigned flags, unsigned long n) { return GlobalAlloc(flags, n); }

/* ---- modules ---------------------------------------------------------- */
HANDLE GetModuleHandleA(LPCSTR name) { return __sys_module_base(name); }
DWORD  GetModuleFileNameA(HANDLE mod, LPSTR buf, DWORD n)
{ return (DWORD)__sys_module_path(mod, buf, n); }
void  *GetProcAddress(HANDLE mod, LPCSTR name)
{
    if ((ULONG_PTR)name >> 16) return __sys_module_proc(mod, name, 0);
    return __sys_module_proc(mod, NULL, (ULONG_PTR)name & 0xFFFF);
}
HANDLE LoadLibraryA(LPCSTR name)
{
    void *h = __sys_module_base(name);
    if (!h) h = __sys_load(name);
    if (!h) last_error = 126;                /* ERROR_MOD_NOT_FOUND */
    return h;
}
HANDLE LoadLibraryExA(LPCSTR name, HANDLE f, DWORD flags) { return LoadLibraryA(name); }
DWORD GetCurrentDirectoryA(DWORD n, LPSTR buf) { return (DWORD)s_strlcpy(buf, "C:\\", n); }
BOOL  DisableThreadLibraryCalls(HANDLE h) { return TRUE; }
void  RtlUnwind(void *frame, void *ret, void *rec, void *rv) { }
BOOL   FreeLibrary(HANDLE h) { return TRUE; }
/* wide variants: the callers in this application only pass ASCII */
static const char *w2a(LPCWSTR w, char *buf, unsigned long n)
{
    unsigned long i = 0;
    if (!w) return NULL;
    for (; i + 1 < n && w[i]; i++) buf[i] = (char)w[i];
    buf[i] = 0;
    return buf;
}
HANDLE LoadLibraryW(LPCWSTR name)
{ char t[260]; return LoadLibraryA(w2a(name, t, sizeof t)); }
HANDLE LoadLibraryExW(LPCWSTR name, HANDLE f, DWORD flags)
{ char t[260]; return LoadLibraryA(w2a(name, t, sizeof t)); }

/* ---- process / environment -------------------------------------------- */
LPSTR GetCommandLineA(void)
{
    if (!cmdline_init) {
        cmdline_init = 1;
        if (!__sys_cmdline(cmdline, sizeof cmdline))
            s_strlcpy(cmdline, "\"app.exe\"", sizeof cmdline);
    }
    return cmdline;
}

typedef struct { DWORD cb; LPSTR r1, d, t; DWORD x, y, xs, ys, xc, yc, fill, flags;
                 WORD show, cbr2; BYTE *r2; HANDLE in, out, err; } STARTUPINFOA;
void GetStartupInfoA(STARTUPINFOA *si)
{ s_memset(si, 0, sizeof *si); si->cb = sizeof *si; si->show = 1; }

typedef struct { DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion,
                       dwBuildNumber, dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
BOOL GetVersionExA(OSVERSIONINFOA *v)
{
    v->dwMajorVersion = 5; v->dwMinorVersion = 0;      /* Windows 2000 */
    v->dwBuildNumber  = 2128;                          /* an AXP64 beta build */
    v->dwPlatformId   = 2;                             /* VER_PLATFORM_WIN32_NT */
    s_memset(v->szCSDVersion, 0, sizeof v->szCSDVersion);
    return TRUE;
}
DWORD GetVersion(void) { return 0x08930005; }
void  ExitProcess(unsigned code) { __sys_exit((int)code); }
BOOL  TerminateProcess(HANDLE h, unsigned code) { __sys_exit((int)code); return TRUE; }
DWORD GetCurrentThreadId(void) { return 1; }
DWORD GetCurrentProcessId(void) { return 0x1234; }
HANDLE GetCurrentProcess(void) { return (HANDLE)(long)-1; }
DWORD GetTickCount(void) { return (DWORD)__sys_ticks(); }

DWORD GetEnvironmentVariableA(LPCSTR name, LPSTR buf, DWORD n)
{ if (n) buf[0] = 0; last_error = 203 /* ENVVAR_NOT_FOUND */; return 0; }
BOOL  SetEnvironmentVariableA(LPCSTR name, LPCSTR val) { return TRUE; }
DWORD ExpandEnvironmentStringsA(LPCSTR src, LPSTR dst, DWORD n)
{ return (DWORD)s_strlcpy(dst, src, n) + 1; }

/* ---- system information ------------------------------------------------ */
typedef struct { WORD wProcessorArchitecture, wReserved; DWORD dwPageSize;
                 LPVOID lpMinimumApplicationAddress, lpMaximumApplicationAddress;
                 ULONG_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors,
                 dwProcessorType, dwAllocationGranularity; WORD wProcessorLevel,
                 wProcessorRevision; } SYSTEM_INFO;
void GetSystemInfo(SYSTEM_INFO *si)
{
    s_memset(si, 0, sizeof *si);
    si->wProcessorArchitecture = 2;          /* PROCESSOR_ARCHITECTURE_ALPHA */
    si->dwPageSize = 0x2000;                 /* Alpha NT uses 8 KiB pages */
    si->lpMinimumApplicationAddress = (LPVOID)0x10000;
    si->lpMaximumApplicationAddress = (LPVOID)0x7FFFFFFF;
    si->dwActiveProcessorMask = 1;
    si->dwNumberOfProcessors = 1;
    si->dwProcessorType = 21064;             /* PROCESSOR_ALPHA_21064 */
    si->dwAllocationGranularity = 0x10000;
    si->wProcessorLevel = 6;
}
typedef struct { DWORD dwLength, dwMemoryLoad; unsigned long ullTotalPhys, ullAvailPhys,
                 ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual; } MEMORYSTATUS;
void GlobalMemoryStatus(MEMORYSTATUS *m)
{
    s_memset(m, 0, sizeof *m);
    m->dwLength = sizeof *m;
    m->dwMemoryLoad = 25;
    m->ullTotalPhys = 256UL << 20;
    m->ullAvailPhys = 192UL << 20;
    m->ullTotalVirtual = 0x7FFF0000UL;
    m->ullAvailVirtual = 0x70000000UL;
}
DWORD GetSystemDefaultLangID(void) { return 0x0409; }
DWORD GetComputerNameA(LPSTR buf, DWORD *n)
{ unsigned long l = s_strlcpy(buf, "AXP64", *n); *n = (DWORD)l; return TRUE; }
DWORD GetWindowsDirectoryA(LPSTR buf, DWORD n) { return (DWORD)s_strlcpy(buf, "C:\\WINNT", n); }
DWORD GetSystemDirectoryA(LPSTR buf, DWORD n)  { return (DWORD)s_strlcpy(buf, "C:\\WINNT\\SYSTEM32", n); }
DWORD GetTempPathA(DWORD n, LPSTR buf)         { return (DWORD)s_strlcpy(buf, "C:\\TEMP\\", n); }
DWORD GetLogicalDrives(void) { return 0x4; }                 /* C: only */
DWORD GetDriveTypeA(LPCSTR root) { return 3; }               /* DRIVE_FIXED */

/* ---- time -------------------------------------------------------------- */
typedef struct { WORD y, mo, dow, d, h, mi, s, ms; } SYSTEMTIME;
typedef struct { DWORD lo, hi; } FILETIME;
void GetLocalTime(SYSTEMTIME *st)
{
    s_memset(st, 0, sizeof *st);
    st->y = 2000; st->mo = 10; st->d = 20; st->h = 18; st->mi = 12;
}
void GetSystemTimeAsFileTime(FILETIME *ft)
{
    unsigned long t = (unsigned long)__sys_time();
    unsigned long v = (t + 11644473600UL) * 10000000UL;
    ft->lo = (DWORD)v; ft->hi = (DWORD)(v >> 32);
}
BOOL FileTimeToLocalFileTime(const FILETIME *a, FILETIME *b) { *b = *a; return TRUE; }
BOOL FileTimeToSystemTime(const FILETIME *a, SYSTEMTIME *st) { GetLocalTime(st); return TRUE; }
long CompareFileTime(const FILETIME *a, const FILETIME *b)
{
    if (a->hi != b->hi) return a->hi < b->hi ? -1 : 1;
    if (a->lo != b->lo) return a->lo < b->lo ? -1 : 1;
    return 0;
}
DWORD GetTimeZoneInformation(void *tz) { if (tz) s_memset(tz, 0, 172); return 0; }

/* ---- critical sections (single-threaded for now) ----------------------- */
typedef struct { long lock; void *owner; } CRITICAL_SECTION;
void InitializeCriticalSection(CRITICAL_SECTION *c) { c->lock = 0; c->owner = NULL; }
void DeleteCriticalSection(CRITICAL_SECTION *c) { c->lock = 0; }
void EnterCriticalSection(CRITICAL_SECTION *c) { c->lock++; }
void LeaveCriticalSection(CRITICAL_SECTION *c) { c->lock--; }

/* ---- files -------------------------------------------------------------- */
#define MAXFD 64
static struct { int used, fd; } fdtab[MAXFD];

HANDLE CreateFileA(LPCSTR name, DWORD access, DWORD share, void *sa,
                   DWORD disp, DWORD flags, HANDLE templ)
{
    long fd = __sys_open(name, (access & 0x40000000) ? 1 : 0);
    if (fd < 0) { last_error = 2; return INVALID_HANDLE_VALUE; }
    for (int i = 1; i < MAXFD; i++)
        if (!fdtab[i].used) { fdtab[i].used = 1; fdtab[i].fd = (int)fd; return (HANDLE)(long)i; }
    __sys_close((int)fd);
    last_error = 4;
    return INVALID_HANDLE_VALUE;
}
static int h2fd(HANDLE h)
{ long i = (long)h; return (i > 0 && i < MAXFD && fdtab[i].used) ? fdtab[i].fd : -1; }

BOOL ReadFile(HANDLE h, void *buf, DWORD n, DWORD *got, void *ov)
{
    int fd = h2fd(h);
    if (fd < 0) { last_error = 6; return FALSE; }
    long r = __sys_read(fd, buf, n);
    if (got) *got = (DWORD)(r < 0 ? 0 : r);
    return r >= 0;
}
BOOL WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *put, void *ov)
{
    int fd = h2fd(h);
    long r = __sys_write(fd < 0 ? 1 : fd, buf, n);
    if (put) *put = (DWORD)(r < 0 ? 0 : r);
    return r >= 0;
}
DWORD SetFilePointer(HANDLE h, long dist, long *hi, DWORD method)
{
    int fd = h2fd(h);
    if (fd < 0) return (DWORD)-1;
    return (DWORD)__sys_seek(fd, dist, (int)method);
}
DWORD GetFileSize(HANDLE h, DWORD *hi)
{
    int fd = h2fd(h);
    long s = fd < 0 ? -1 : __sys_fsize(fd);
    if (hi) *hi = 0;
    return (DWORD)s;
}
BOOL CloseHandle(HANDLE h)
{
    long i = (long)h;
    if (i > 0 && i < MAXFD && fdtab[i].used) { __sys_close(fdtab[i].fd); fdtab[i].used = 0; return TRUE; }
    return TRUE;
}
DWORD GetFileType(HANDLE h) { return 1; }                    /* FILE_TYPE_DISK */
DWORD GetFileAttributesA(LPCSTR name)
{
    long fd = __sys_open(name, 0);
    if (fd < 0) { last_error = 2; return (DWORD)-1; }
    __sys_close((int)fd);
    return 0x80;                                             /* FILE_ATTRIBUTE_NORMAL */
}
DWORD GetFullPathNameA(LPCSTR name, DWORD n, LPSTR buf, LPSTR *part)
{
    unsigned long l = s_strlcpy(buf, name, n);
    if (part) {
        *part = buf;
        for (char *p = buf; *p; p++) if (*p == '\\' || *p == '/') *part = p + 1;
    }
    return (DWORD)l;
}
DWORD GetShortPathNameA(LPCSTR l, LPSTR s, DWORD n) { return (DWORD)s_strlcpy(s, l, n); }
BOOL  DeleteFileA(LPCSTR name) { return TRUE; }

/* ---- misc stubs the startup path touches -------------------------------- */
void  OutputDebugStringA(LPCSTR s) { __sys_debug(s); }
DWORD FormatMessageA(DWORD f, const void *src, DWORD id, DWORD lang,
                     LPSTR buf, DWORD n, void *args)
{ return (DWORD)s_strlcpy(buf, "error", n); }
int   GetLocaleInfoA(DWORD locale, DWORD type, LPSTR buf, int n)
{ return (int)s_strlcpy(buf, "", n) + 1; }
int   GetDateFormatA(DWORD l, DWORD f, const SYSTEMTIME *st, LPCSTR fmt, LPSTR buf, int n)
{ return (int)s_strlcpy(buf, "20/10/2000", n) + 1; }
int   GetTimeFormatA(DWORD l, DWORD f, const SYSTEMTIME *st, LPCSTR fmt, LPSTR buf, int n)
{ return (int)s_strlcpy(buf, "18:12:42", n) + 1; }
BOOL  FlushInstructionCache(HANDLE p, const void *a, unsigned long n) { return TRUE; }
HANDLE CreateEventA(void *sa, BOOL manual, BOOL init, LPCSTR name) { return (HANDLE)1; }
BOOL  SetEvent(HANDLE h) { return TRUE; }
DWORD WaitForSingleObject(HANDLE h, DWORD ms) { return 0; }
DWORD ResumeThread(HANDLE h) { return 1; }
BOOL  TerminateThread(HANDLE h, DWORD c) { return TRUE; }
void  RaiseException(DWORD code, DWORD f, DWORD n, const void *a)
{ __sys_debug("kernel32: RaiseException\n"); __sys_exit(1); }

void DllMain(void) { }
