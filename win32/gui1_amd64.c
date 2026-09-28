/* The same program as gui1.c, built for amd64 so that the AXP64 build of
 * depends.exe has a target whose dependencies it cannot resolve — the
 * mirror image of giving the amd64 build an AXP64 target. */
#include <windows.h>

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(64, 96, 160));
    wc.lpszClassName = "Gui1Amd64";
    RegisterClassA(&wc);
    HWND h = CreateWindowExA(0, "Gui1Amd64", "gui1 (amd64)", WS_OVERLAPPEDWINDOW,
                             100, 100, 420, 260, NULL, NULL, hInst, NULL);
    ShowWindow(h, show); UpdateWindow(h);
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    return 0;
}
