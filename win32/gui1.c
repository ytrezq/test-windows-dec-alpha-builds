/* gui1.exe — an AXP64 (DEC Alpha) Win32 GUI application.
 *
 * This is the milestone: a real window, created and painted entirely by
 * Alpha code running under the JIT.  Every USER32/GDI32 call here executes
 * Alpha instructions in our thin user32/gdi32, which cross the single host
 * gate into Wine's real window manager and GDI.  The WndProc is an Alpha
 * function; when Wine dispatches a message it calls this Alpha address, the
 * non-executable guest page faults, and the host runs it through the JIT.
 */
typedef unsigned int        UINT;
typedef unsigned int        DWORD;
typedef int                 BOOL;
typedef unsigned int        COLORREF;
typedef void               *HWND;
typedef void               *HDC;
typedef void               *HINSTANCE;
typedef void               *HBRUSH;
typedef void               *HGDIOBJ;
typedef void               *HCURSOR;
typedef const char         *LPCSTR;
typedef unsigned long long  UINT_PTR;
typedef unsigned long long  WPARAM;
typedef long long           LPARAM;
typedef long long           LRESULT;
#define NULL ((void*)0)

/* Win32 structures — laid out to match Win64/Wine exactly. */
typedef struct { int left, top, right, bottom; } RECT;
typedef struct { int x, y; } POINT;
typedef struct {
    UINT   style;                 /* 0  */
    LRESULT (*lpfnWndProc)(HWND,UINT,WPARAM,LPARAM);  /* 8  */
    int    cbClsExtra;            /* 16 */
    int    cbWndExtra;            /* 20 */
    HINSTANCE hInstance;          /* 24 */
    void  *hIcon;                 /* 32 */
    HCURSOR hCursor;              /* 40 */
    HBRUSH hbrBackground;         /* 48 */
    LPCSTR lpszMenuName;          /* 56 */
    LPCSTR lpszClassName;         /* 64 */
} WNDCLASSA;                      /* size 72 */
typedef struct {
    HDC  hdc;                     /* 0  */
    BOOL fErase;                  /* 8  */
    RECT rcPaint;                 /* 12 */
    BOOL fRestore;                /* 28 */
    BOOL fIncUpdate;              /* 32 */
    unsigned char rgbReserved[32];/* 36 */
} PAINTSTRUCT;                    /* size 72 */

/* ---- imports from our AXP64 USER32 / GDI32 ---------------------------- */
extern DWORD   RegisterClassA(const WNDCLASSA *);
extern HWND    CreateWindowExA(DWORD,LPCSTR,LPCSTR,DWORD,int,int,int,int,HWND,void*,HINSTANCE,void*);
extern BOOL    ShowWindow(HWND,int);
extern BOOL    UpdateWindow(HWND);
extern BOOL    DestroyWindow(HWND);
extern LRESULT DefWindowProcA(HWND,UINT,WPARAM,LPARAM);
extern int     GetMessageA(void*,HWND,UINT,UINT);
extern BOOL    TranslateMessage(const void*);
extern LRESULT DispatchMessageA(const void*);
extern void    PostQuitMessage(int);
extern HDC     BeginPaint(HWND,PAINTSTRUCT*);
extern BOOL    EndPaint(HWND,const PAINTSTRUCT*);
extern BOOL    GetClientRect(HWND,RECT*);
extern HCURSOR LoadCursorA(HINSTANCE,LPCSTR);
extern UINT_PTR SetTimer(HWND,UINT_PTR,UINT,void*);

extern HBRUSH  CreateSolidBrush(COLORREF);
extern BOOL    DeleteObject(HGDIOBJ);
extern int     SetBkMode(HDC,int);
extern COLORREF SetTextColor(HDC,COLORREF);
extern BOOL    TextOutA(HDC,int,int,LPCSTR,int);
extern BOOL    Ellipse(HDC,int,int,int,int);
extern BOOL    MoveToEx(HDC,int,int,void*);
extern BOOL    LineTo(HDC,int,int);

/* ---- from KERNEL32 (for logging / exit) ------------------------------- */
extern void    OutputDebugStringA(LPCSTR);
extern void    ExitProcess(unsigned);

#define WS_OVERLAPPEDWINDOW 0x00CF0000u
#define SW_SHOW    5
#define WM_DESTROY 0x0002
#define WM_PAINT   0x000F
#define WM_TIMER   0x0113
#define TRANSPARENT 1
#define IDC_ARROW  ((LPCSTR)(unsigned long)32512)
#define RGB(r,g,b) ((COLORREF)((unsigned char)(r)|((unsigned char)(g)<<8)|((unsigned char)(b)<<16)))

static unsigned long slen(const char *s){ const char *p=s; while(*p)p++; return (unsigned long)(p-s); }
static void zero(void *d, unsigned long n){ unsigned char *p=d; while(n--) *p++=0; }

static LRESULT WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; zero(&ps, sizeof ps);
        HDC dc = BeginPaint(h, &ps);
        HBRUSH band = CreateSolidBrush(RGB(0, 90, 160));
        RECT r; zero(&r, sizeof r); GetClientRect(h, &r);
        RECT top; top.left=10; top.top=10; top.right=r.right-10; top.bottom=60;
        extern int FillRect(HDC, const void*, HBRUSH);
        FillRect(dc, &top, band);
        DeleteObject(band);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255,255,255));
        const char *t = "AXP64 sous le JIT : premiere fenetre";
        TextOutA(dc, 20, 26, t, (int)slen(t));
        Ellipse(dc, 20, 80, 120, 180);
        MoveToEx(dc, 140, 90, NULL);
        LineTo(dc, 300, 190);
        EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_TIMER) { DestroyWindow(h); return 0; }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(h, m, w, l);
}

void entry(void)
{
    OutputDebugStringA("[gui1] Alpha app starting\n");
    HINSTANCE inst = (HINSTANCE)(unsigned long)0x11110000;
    WNDCLASSA wc; zero(&wc, sizeof wc);
    wc.style = 0x0003;                         /* CS_HREDRAW|CS_VREDRAW */
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(245, 245, 245));
    wc.lpszClassName = "axp64win";
    DWORD atom = RegisterClassA(&wc);
    OutputDebugStringA(atom ? "[gui1] class registered\n" : "[gui1] RegisterClass FAILED\n");

    HWND h = CreateWindowExA(0, "axp64win", "Fenetre AXP64",
                             WS_OVERLAPPEDWINDOW, 40, 40, 440, 280,
                             NULL, NULL, inst, NULL);
    OutputDebugStringA(h ? "[gui1] window created\n" : "[gui1] CreateWindow FAILED\n");
    if (!h) ExitProcess(1);

    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
    SetTimer(h, 1, 45000, NULL);               /* self-close after 45s */

    OutputDebugStringA("[gui1] entering message loop\n");
    unsigned char msg[64];
    while (GetMessageA(msg, NULL, 0, 0) > 0) {
        TranslateMessage(msg);
        DispatchMessageA(msg);
    }
    OutputDebugStringA("[gui1] message loop done\n");
    ExitProcess(0);
}
