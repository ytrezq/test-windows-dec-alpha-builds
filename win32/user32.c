/* user32.dll for Windows AXP64 — compiled to DEC Alpha code.
 *
 * These are thin PE-side stubs: each Win32 entry point runs as Alpha code
 * and forwards to the host through a __gu_* gate, which calls Wine's real
 * user32.  When the Wine-side implementation is later replaced by a port of
 * Wine's own user32 C sources, only this file changes; the app above and the
 * host below stay put.  The forwarding keeps the homogeneous rule: calling
 * RegisterClassA executes Alpha instructions that then cross the one gate.
 */
typedef unsigned int        UINT;
typedef unsigned int        DWORD;
typedef int                 BOOL;
typedef int                 INT;
typedef void               *HANDLE;
typedef void               *HWND;
typedef void               *HDC;
typedef void               *HINSTANCE;
typedef void               *HMENU;
typedef void               *HICON;
typedef void               *HCURSOR;
typedef void               *HBRUSH;
typedef void               *LPVOID;
typedef const char         *LPCSTR;
typedef unsigned long long  UINT_PTR;
typedef unsigned long long  WPARAM;
typedef long long           LPARAM;
typedef long long           LRESULT;
#define NULL ((void*)0)

/* ---- the one boundary: host gates (become native thunks) -------------- */
extern DWORD    __gu_RegisterClassA(const void *wc);
extern DWORD    __gu_RegisterClassExA(const void *wc);
extern HWND     __gu_CreateWindowExA(const void *packed);
extern BOOL     __gu_ShowWindow(HWND, int);
extern BOOL     __gu_UpdateWindow(HWND);
extern BOOL     __gu_DestroyWindow(HWND);
extern LRESULT  __gu_DefWindowProcA(HWND, UINT, WPARAM, LPARAM);
extern INT      __gu_GetMessageA(void *msg, HWND, UINT, UINT);
extern BOOL     __gu_PeekMessageA(void *msg, HWND, UINT, UINT, UINT);
extern BOOL     __gu_TranslateMessage(const void *msg);
extern LRESULT  __gu_DispatchMessageA(const void *msg);
extern void     __gu_PostQuitMessage(int);
extern BOOL     __gu_PostMessageA(HWND, UINT, WPARAM, LPARAM);
extern LRESULT  __gu_SendMessageA(HWND, UINT, WPARAM, LPARAM);
extern HDC      __gu_BeginPaint(HWND, void *ps);
extern BOOL     __gu_EndPaint(HWND, const void *ps);
extern BOOL     __gu_GetClientRect(HWND, void *rect);
extern BOOL     __gu_InvalidateRect(HWND, const void *rect, BOOL erase);
extern INT      __gu_FillRect(HDC, const void *rect, HBRUSH);
extern HCURSOR  __gu_LoadCursorA(HINSTANCE, LPCSTR);
extern HICON    __gu_LoadIconA(HINSTANCE, LPCSTR);
extern UINT_PTR __gu_SetTimer(HWND, UINT_PTR, UINT, void *proc);
extern BOOL     __gu_KillTimer(HWND, UINT_PTR);
extern INT      __gu_GetSystemMetrics(int);
extern INT      __gu_MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
extern BOOL     __gu_SetWindowTextA(HWND, LPCSTR);
extern BOOL     __gu_MoveWindow(HWND, int, int, int, int, BOOL);

/* ---- exported Win32 surface ------------------------------------------- */
DWORD   RegisterClassA(const void *wc)               { return __gu_RegisterClassA(wc); }
DWORD   RegisterClassExA(const void *wc)             { return __gu_RegisterClassExA(wc); }
BOOL    ShowWindow(HWND h, int c)                    { return __gu_ShowWindow(h, c); }
BOOL    UpdateWindow(HWND h)                         { return __gu_UpdateWindow(h); }
BOOL    DestroyWindow(HWND h)                        { return __gu_DestroyWindow(h); }
LRESULT DefWindowProcA(HWND h, UINT m, WPARAM w, LPARAM l) { return __gu_DefWindowProcA(h,m,w,l); }
INT     GetMessageA(void *msg, HWND h, UINT a, UINT b){ return __gu_GetMessageA(msg,h,a,b); }
BOOL    PeekMessageA(void *msg, HWND h, UINT a, UINT b, UINT r){ return __gu_PeekMessageA(msg,h,a,b,r); }
BOOL    TranslateMessage(const void *msg)            { return __gu_TranslateMessage(msg); }
LRESULT DispatchMessageA(const void *msg)            { return __gu_DispatchMessageA(msg); }
void    PostQuitMessage(int n)                       { __gu_PostQuitMessage(n); }
BOOL    PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l){ return __gu_PostMessageA(h,m,w,l); }
LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l){ return __gu_SendMessageA(h,m,w,l); }
HDC     BeginPaint(HWND h, void *ps)                 { return __gu_BeginPaint(h, ps); }
BOOL    EndPaint(HWND h, const void *ps)             { return __gu_EndPaint(h, ps); }
BOOL    GetClientRect(HWND h, void *r)               { return __gu_GetClientRect(h, r); }
BOOL    InvalidateRect(HWND h, const void *r, BOOL e){ return __gu_InvalidateRect(h, r, e); }
INT     FillRect(HDC dc, const void *r, HBRUSH b)    { return __gu_FillRect(dc, r, b); }
HCURSOR LoadCursorA(HINSTANCE i, LPCSTR n)           { return __gu_LoadCursorA(i, n); }
HICON   LoadIconA(HINSTANCE i, LPCSTR n)             { return __gu_LoadIconA(i, n); }
UINT_PTR SetTimer(HWND h, UINT_PTR id, UINT el, void *p){ return __gu_SetTimer(h, id, el, p); }
BOOL    KillTimer(HWND h, UINT_PTR id)               { return __gu_KillTimer(h, id); }
INT     GetSystemMetrics(int i)                      { return __gu_GetSystemMetrics(i); }
INT     MessageBoxA(HWND h, LPCSTR t, LPCSTR c, UINT y){ return __gu_MessageBoxA(h,t,c,y); }
BOOL    SetWindowTextA(HWND h, LPCSTR s)             { return __gu_SetWindowTextA(h, s); }
BOOL    MoveWindow(HWND h, int x, int y, int w, int t, BOOL r){ return __gu_MoveWindow(h,x,y,w,t,r); }

/* CreateWindowExA has 12 arguments; pack them into the layout the host
 * expects (uint64 ex,cls,name,style; int32 x,y,w,h; uint64 parent,menu,
 * inst,param) and pass one pointer through the gate. */
typedef struct { unsigned long long ex, cls, name, style;
    int x, y, w, h;
    unsigned long long parent, menu, inst, param; } CWArgs;
HWND CreateWindowExA(DWORD ex, LPCSTR cls, LPCSTR name, DWORD style,
                     int x, int y, int w, int h,
                     HWND parent, HMENU menu, HINSTANCE inst, LPVOID param)
{
    CWArgs a;
    a.ex=(unsigned long long)ex; a.cls=(unsigned long long)(unsigned long)cls;
    a.name=(unsigned long long)(unsigned long)name; a.style=(unsigned long long)style;
    a.x=x; a.y=y; a.w=w; a.h=h;
    a.parent=(unsigned long long)(unsigned long)parent;
    a.menu=(unsigned long long)(unsigned long)menu;
    a.inst=(unsigned long long)(unsigned long)inst;
    a.param=(unsigned long long)(unsigned long)param;
    return __gu_CreateWindowExA(&a);
}

/* CreateWindowA is CreateWindowExA with dwExStyle = 0. */
HWND CreateWindowA(LPCSTR cls, LPCSTR name, DWORD style, int x, int y, int w, int h,
                   HWND parent, HMENU menu, HINSTANCE inst, LPVOID param)
{ return CreateWindowExA(0, cls, name, style, x, y, w, h, parent, menu, inst, param); }

/* DllMain */
int DllMain(void *inst, unsigned reason, void *reserved) { return 1; }

/* Menus come out of the calling module's own resources, which live in the
 * guest image, so this one goes through the resource gate rather than Wine. */
extern void *__gu_LoadMenuFromModule(void *mod, DWORD id);
void *LoadMenuA(void *inst, LPCSTR name)
{ return __gu_LoadMenuFromModule(inst, (DWORD)(unsigned long)name); }

/* wsprintfA is variadic.  Taking eight fixed arguments and passing them
 * straight through keeps the Alpha argument list intact: the first six are
 * already in a0..a5 and the rest are re-laid at the same stack offsets for
 * the gate call, which is exactly where the host reads them. */
typedef long long LLV;
extern LLV __gu_wsprintfA(LLV a, LLV b, LLV c, LLV d, LLV e, LLV f, LLV g, LLV h);
int wsprintfA(LLV a, LLV b, LLV c, LLV d, LLV e, LLV f, LLV g, LLV h)
{ return (int)__gu_wsprintfA(a, b, c, d, e, f, g, h); }
