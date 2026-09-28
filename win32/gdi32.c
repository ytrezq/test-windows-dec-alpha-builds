/* gdi32.dll for Windows AXP64 — compiled to DEC Alpha code.
 * Thin PE-side stubs forwarding to the host's Wine gdi32 through __gd_* gates.
 */
typedef unsigned int        UINT;
typedef unsigned int        DWORD;
typedef int                 BOOL;
typedef int                 INT;
typedef unsigned int        COLORREF;
typedef void               *HDC;
typedef void               *HGDIOBJ;
typedef void               *HBRUSH;
typedef void               *HPEN;
typedef const char         *LPCSTR;
#define NULL ((void*)0)

extern HBRUSH   __gd_CreateSolidBrush(COLORREF);
extern BOOL     __gd_DeleteObject(HGDIOBJ);
extern INT      __gd_SetBkMode(HDC, int);
extern COLORREF __gd_SetTextColor(HDC, COLORREF);
extern COLORREF __gd_SetBkColor(HDC, COLORREF);
extern BOOL     __gd_TextOutA(HDC, int, int, LPCSTR, int);
extern BOOL     __gd_Ellipse(HDC, int, int, int, int);
extern BOOL     __gd_Rectangle(HDC, int, int, int, int);
extern BOOL     __gd_MoveToEx(HDC, int, int, void *);
extern BOOL     __gd_LineTo(HDC, int, int);
extern HGDIOBJ  __gd_SelectObject(HDC, HGDIOBJ);
extern HPEN     __gd_CreatePen(int, int, COLORREF);
extern HGDIOBJ  __gd_GetStockObject(int);
extern COLORREF __gd_SetPixel(HDC, int, int, COLORREF);

HBRUSH   CreateSolidBrush(COLORREF c)                 { return __gd_CreateSolidBrush(c); }
BOOL     DeleteObject(HGDIOBJ o)                      { return __gd_DeleteObject(o); }
INT      SetBkMode(HDC dc, int m)                     { return __gd_SetBkMode(dc, m); }
COLORREF SetTextColor(HDC dc, COLORREF c)             { return __gd_SetTextColor(dc, c); }
COLORREF SetBkColor(HDC dc, COLORREF c)               { return __gd_SetBkColor(dc, c); }
BOOL     TextOutA(HDC dc, int x, int y, LPCSTR s, int n){ return __gd_TextOutA(dc,x,y,s,n); }
BOOL     Ellipse(HDC dc, int a, int b, int c, int d)  { return __gd_Ellipse(dc,a,b,c,d); }
BOOL     Rectangle(HDC dc, int a, int b, int c, int d){ return __gd_Rectangle(dc,a,b,c,d); }
BOOL     MoveToEx(HDC dc, int x, int y, void *p)      { return __gd_MoveToEx(dc,x,y,p); }
BOOL     LineTo(HDC dc, int x, int y)                 { return __gd_LineTo(dc,x,y); }
HGDIOBJ  SelectObject(HDC dc, HGDIOBJ o)              { return __gd_SelectObject(dc,o); }
HPEN     CreatePen(int s, int w, COLORREF c)          { return __gd_CreatePen(s,w,c); }
HGDIOBJ  GetStockObject(int i)                        { return __gd_GetStockObject(i); }
COLORREF SetPixel(HDC dc, int x, int y, COLORREF c)   { return __gd_SetPixel(dc,x,y,c); }

int DllMain(void *inst, unsigned reason, void *reserved) { return 1; }
