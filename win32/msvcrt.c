/* msvcrt.dll for Windows AXP64 — compiled to DEC Alpha code.
 *
 * Besides the usual C runtime, this provides the _Ots* helpers that the
 * Microsoft Alpha compiler emits calls to for block moves, fills and
 * 32-bit division (the Alpha has no integer divide instruction).
 */
typedef unsigned long  size_t_;
typedef unsigned int   uint32;
typedef unsigned long  uint64;
#define NULL ((void*)0)

extern void *__sys_mem(unsigned long size);
extern void  __sys_debug(const char *s);
extern void  __sys_exit(int code);
extern long  __sys_write(int fd, const void *buf, unsigned long len);

/* ---- heap ------------------------------------------------------------- */
#define BLK 0x100000
static unsigned char *hp, *he;
static void *xalloc(size_t_ n)
{
    n = (n + 15) & ~15UL;
    if (hp + n > he) {
        size_t_ want = n > BLK ? n : BLK;
        hp = __sys_mem(want);
        if (!hp) return NULL;
        he = hp + want;
    }
    void *p = hp; hp += n; return p;
}

/* ---- memory / string --------------------------------------------------- */
void *memset(void *d, int c, size_t_ n)
{ unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t_ n)
{ unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }
void *memmove(void *d, const void *s, size_t_ n)
{
    unsigned char *p = d; const unsigned char *q = s;
    if (p < q) { while (n--) *p++ = *q++; }
    else { p += n; q += n; while (n--) *--p = *--q; }
    return d;
}
int memcmp(const void *a, const void *b, size_t_ n)
{
    const unsigned char *x = a, *y = b;
    for (; n--; x++, y++) if (*x != *y) return *x < *y ? -1 : 1;
    return 0;
}
size_t_ strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t_)(p - s); }
char *strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++)) ; return r; }
char *strncpy(char *d, const char *s, size_t_ n)
{ char *r = d; while (n && (*d = *s)) { d++; s++; n--; } while (n--) *d++ = 0; return r; }
char *strcat(char *d, const char *s) { char *r = d; while (*d) d++; while ((*d++ = *s++)) ; return r; }
int strcmp(const char *a, const char *b)
{ for (; *a && *a == *b; a++, b++) ; return (unsigned char)*a - (unsigned char)*b; }
int strncmp(const char *a, const char *b, size_t_ n)
{ for (; n && *a && *a == *b; a++, b++, n--) ; return n ? (unsigned char)*a - (unsigned char)*b : 0; }
char *strchr(const char *s, int c)
{ for (; *s; s++) if (*s == (char)c) return (char *)s; return c ? NULL : (char *)s; }
char *strrchr(const char *s, int c)
{ const char *r = NULL; for (; *s; s++) if (*s == (char)c) r = s; return (char *)(c ? r : s); }
char *strstr(const char *h, const char *n)
{
    if (!*n) return (char *)h;
    for (; *h; h++) {
        const char *a = h, *b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return (char *)h;
    }
    return NULL;
}
size_t_ strcspn(const char *s, const char *rej)
{
    const char *p = s;
    for (; *p; p++) for (const char *r = rej; *r; r++) if (*p == *r) return (size_t_)(p - s);
    return (size_t_)(p - s);
}
static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
static int upper(int c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
int _stricmp(const char *a, const char *b)
{ for (; *a && lower(*a) == lower(*b); a++, b++) ; return lower((unsigned char)*a) - lower((unsigned char)*b); }
int _strcmpi(const char *a, const char *b) { return _stricmp(a, b); }
int _strnicmp(const char *a, const char *b, size_t_ n)
{ for (; n && *a && lower(*a) == lower(*b); a++, b++, n--) ; return n ? lower((unsigned char)*a) - lower((unsigned char)*b) : 0; }
char *_strlwr(char *s) { for (char *p = s; *p; p++) *p = (char)lower(*p); return s; }
char *_strupr(char *s) { for (char *p = s; *p; p++) *p = (char)upper(*p); return s; }
char *_strdup(const char *s)
{ size_t_ n = strlen(s) + 1; char *p = xalloc(n); if (p) memcpy(p, s, n); return p; }
static char *tok_save;
char *strtok(char *s, const char *sep)
{
    if (!s) s = tok_save;
    if (!s) return NULL;
    while (*s && strchr(sep, *s)) s++;
    if (!*s) { tok_save = NULL; return NULL; }
    char *start = s;
    while (*s && !strchr(sep, *s)) s++;
    if (*s) { *s = 0; tok_save = s + 1; } else tok_save = NULL;
    return start;
}
unsigned long strtoul(const char *s, char **end, int base)
{
    unsigned long v = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (base == 16 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!base) {
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (s[0] == '0') base = 8; else base = 10;
    }
    for (;; s++) {
        int c = *s, d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned long)base + (unsigned long)d;
    }
    if (end) *end = (char *)s;
    return v;
}
size_t_ wcslen(const unsigned short *s) { const unsigned short *p = s; while (*p) p++; return (size_t_)(p - s); }
int _wcsicmp(const unsigned short *a, const unsigned short *b)
{ for (; *a && lower(*a) == lower(*b); a++, b++) ; return lower(*a) - lower(*b); }
size_t_ wcstombs(char *d, const unsigned short *s, size_t_ n)
{ size_t_ i = 0; for (; i < n && s[i]; i++) d[i] = (char)s[i]; if (i < n) d[i] = 0; return i; }

/* ---- ctype ------------------------------------------------------------- */
int isdigit(int c) { return c >= '0' && c <= '9'; }
int isalpha(int c) { return (c | 32) >= 'a' && (c | 32) <= 'z'; }
int isspace(int c) { return c == ' ' || (c >= 9 && c <= 13); }
int isupper(int c) { return c >= 'A' && c <= 'Z'; }
int islower(int c) { return c >= 'a' && c <= 'z'; }
int isalnum(int c) { return isalpha(c) || isdigit(c); }
int isxdigit(int c) { return isdigit(c) || ((c | 32) >= 'a' && (c | 32) <= 'f'); }
int isprint(int c) { return c >= 0x20 && c < 0x7F; }
int toupper(int c) { return upper(c); }
int tolower(int c) { return lower(c); }

/* ---- Alpha compiler support routines (_Ots*) ---------------------------
 * The Microsoft Alpha compiler calls these for block operations and for
 * integer division, which the Alpha has no instruction for. */
void _OtsZero(void *d, uint64 n)             { memset(d, 0, (size_t_)n); }
void _OtsFill(void *d, uint64 n, int c)      { memset(d, c, (size_t_)n); }
void _OtsMove(void *d, const void *s, uint64 n) { memmove(d, s, (size_t_)n); }
uint64 _Otsstrlen(const char *s)             { return strlen(s); }
char  *_Otsstrcpy(char *d, const char *s)    { return strcpy(d, s); }
int    _Otsstrcmp(const char *a, const char *b) { return strcmp(a, b); }
/* signed 32-bit divide; the quotient is returned, remainder via the ABI's
 * second return slot is not used by the compiler's call sequence */
int _OtsDivide32(int a, int b)               { return b ? a / b : 0; }
unsigned _OtsDivide32Unsigned(unsigned a, unsigned b) { return b ? a / b : 0; }
int _OtsRemainder32(int a, int b)            { return b ? a % b : 0; }
long _OtsDivide64(long a, long b)            { return b ? a / b : 0; }
unsigned long _OtsDivide64Unsigned(unsigned long a, unsigned long b) { return b ? a / b : 0; }
long _OtsRemainder64(long a, long b)         { return b ? a % b : 0; }

/* ---- sorting ------------------------------------------------------------ */
static void swapb(char *a, char *b, size_t_ n) { while (n--) { char t = *a; *a++ = *b; *b++ = t; } }
void qsort(void *base, size_t_ n, size_t_ sz, int (*cmp)(const void *, const void *))
{
    char *b = base;
    for (size_t_ i = 1; i < n; i++)             /* insertion sort: small n here */
        for (size_t_ j = i; j && cmp(b + (j - 1) * sz, b + j * sz) > 0; j--)
            swapb(b + (j - 1) * sz, b + j * sz, sz);
}

/* ---- formatted output ---------------------------------------------------- */
#include <stdarg.h>
typedef struct { char *buf; size_t_ cap, len; } Sink;
static void emit(Sink *s, char c) { if (s->len + 1 < s->cap) s->buf[s->len] = c; s->len++; }
static void emits(Sink *s, const char *p) { while (*p) emit(s, *p++); }
static void emitnum(Sink *s, uint64 v, int base, int upper_, int width, char pad, int neg)
{
    char t[32]; int n = 0;
    const char *dig = upper_ ? "0123456789ABCDEF" : "0123456789abcdef";
    if (!v) t[n++] = '0';
    while (v) { t[n++] = dig[v % (uint64)base]; v /= (uint64)base; }
    if (neg) t[n++] = '-';
    for (int k = n; k < width; k++) emit(s, pad);
    while (n) emit(s, t[--n]);
}
static int vformat(Sink *s, const char *f, va_list ap)
{
    for (; *f; f++) {
        if (*f != '%') { emit(s, *f); continue; }
        f++;
        int left = 0, width = 0, longf = 0, prec = -1;
        char pad = ' ';
        for (;; f++) {
            if (*f == '-') left = 1;
            else if (*f == '0') pad = '0';
            else if (*f == '+' || *f == ' ' || *f == '#') ;
            else break;
        }
        while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        if (*f == '.') { f++; prec = 0; while (*f >= '0' && *f <= '9') prec = prec * 10 + (*f++ - '0'); }
        while (*f == 'l' || *f == 'h' || *f == 'I' || *f == '6' || *f == '4') { if (*f == 'l') longf++; f++; }
        switch (*f) {
        case 'd': case 'i': {
            long v = longf ? va_arg(ap, long) : va_arg(ap, int);
            uint64 u = v < 0 ? (uint64)(-v) : (uint64)v;
            emitnum(s, u, 10, 0, width, pad, v < 0); break;
        }
        case 'u': emitnum(s, longf ? va_arg(ap, unsigned long) : va_arg(ap, unsigned), 10, 0, width, pad, 0); break;
        case 'x': emitnum(s, longf ? va_arg(ap, unsigned long) : va_arg(ap, unsigned), 16, 0, width, pad, 0); break;
        case 'X': emitnum(s, longf ? va_arg(ap, unsigned long) : va_arg(ap, unsigned), 16, 1, width, pad, 0); break;
        case 'o': emitnum(s, longf ? va_arg(ap, unsigned long) : va_arg(ap, unsigned), 8, 0, width, pad, 0); break;
        case 'p': emitnum(s, (uint64)va_arg(ap, void *), 16, 0, 16, '0', 0); break;
        case 'c': emit(s, (char)va_arg(ap, int)); break;
        case 's': {
            const char *p = va_arg(ap, const char *);
            if (!p) p = "(null)";
            int n = 0; while (p[n] && (prec < 0 || n < prec)) n++;
            if (!left) for (int k = n; k < width; k++) emit(s, ' ');
            for (int k = 0; k < n; k++) emit(s, p[k]);
            if (left) for (int k = n; k < width; k++) emit(s, ' ');
            break;
        }
        case '%': emit(s, '%'); break;
        default: emit(s, '%'); if (*f) emit(s, *f); break;
        }
    }
    if (s->cap) s->buf[s->len < s->cap ? s->len : s->cap - 1] = 0;
    return (int)s->len;
}
int _vsnprintf(char *buf, size_t_ n, const char *f, va_list ap)
{ Sink s = { buf, n, 0 }; return vformat(&s, f, ap); }
int _snprintf(char *buf, size_t_ n, const char *f, ...)
{ va_list ap; va_start(ap, f); Sink s = { buf, n, 0 }; int r = vformat(&s, f, ap); va_end(ap); return r; }
int sprintf(char *buf, const char *f, ...)
{ va_list ap; va_start(ap, f); Sink s = { buf, (size_t_)-1, 0 }; int r = vformat(&s, f, ap); va_end(ap); return r; }
int vsprintf(char *buf, const char *f, va_list ap)
{ Sink s = { buf, (size_t_)-1, 0 }; return vformat(&s, f, ap); }
int printf(const char *f, ...)
{
    char tmp[1024];
    va_list ap; va_start(ap, f);
    Sink s = { tmp, sizeof tmp, 0 };
    int r = vformat(&s, f, ap);
    va_end(ap);
    __sys_write(1, tmp, (unsigned long)(s.len < sizeof tmp ? s.len : sizeof tmp - 1));
    return r;
}

/* ---- C++ operators ------------------------------------------------------ */
void *op_new(size_t_ n)        { void *p = xalloc(n ? n : 1); return p; }
void  op_delete(void *p)       { (void)p; }
void *op_new_array(size_t_ n)  { return op_new(n); }
void  op_delete_array(void *p) { (void)p; }
void  free(void *p)            { (void)p; }
void *malloc(size_t_ n)        { return xalloc(n); }
void *calloc(size_t_ a, size_t_ b) { void *p = xalloc(a * b); if (p) memset(p, 0, a * b); return p; }
void *realloc(void *p, size_t_ n) { void *q = xalloc(n); if (p && q) memcpy(q, p, n); return q; }

/* ---- CRT startup / shutdown --------------------------------------------- */
int   __argc;
char **__argv;
int   _fmode;
int   _commode;
char *_acmdln;
static char  argv0[] = "depends.exe";
static char *argv_storage[2] = { argv0, NULL };

void __set_app_type(int t) { (void)t; }
void __setusermatherr(void *f) { (void)f; }
int  _setmbcp(int cp) { (void)cp; return 0; }
long _XcptFilter(unsigned code, void *info) { (void)code; (void)info; return 0; }

void __getmainargs(int *argc, char ***argv, char ***env, int expand, void *newmode)
{
    __argc = 1;
    __argv = argv_storage;
    _acmdln = argv0;
    if (argc) *argc = 1;
    if (argv) *argv = argv_storage;
    if (env)  *env = NULL;
    (void)expand; (void)newmode;
}
typedef void (*initfn)(void);
void _initterm(initfn *first, initfn *last)
{ for (; first < last; first++) if (*first) (*first)(); }

typedef int (*onexitfn)(void);
void *_onexit(void *f) { return f; }
void *__dllonexit(void *f, void ***a, void ***b) { (void)a; (void)b; return f; }

void exit(int code)   { __sys_exit(code); }
void _exit(int code)  { __sys_exit(code); }
void _cexit(void)     { }
void _c_exit(void)    { }
void abort(void)      { __sys_debug("msvcrt: abort\n"); __sys_exit(3); }
void _purecall(void)  { __sys_debug("msvcrt: pure virtual call\n"); __sys_exit(3); }

/* Exception dispatch: the real ones walk the Alpha .pdata unwind tables.
 * Until SEH is implemented these report and stop rather than corrupt state. */
long _CxxFrameHandler(void *rec, void *frame, void *ctx, void *disp)
{ __sys_debug("msvcrt: _CxxFrameHandler (SEH not implemented)\n"); __sys_exit(4); return 1; }
long _OtsCSpecificHandler(void *rec, void *frame, void *ctx, void *disp)
{ __sys_debug("msvcrt: _OtsCSpecificHandler (SEH not implemented)\n"); __sys_exit(4); return 1; }

void DllMain(void) { }
