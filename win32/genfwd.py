#!/usr/bin/env python3
"""Generate the thin AXP64 forwarding DLLs and their host gates.

Each entry is "Name ret arg1 arg2 ...", with types:
    v void      i int32    u uint32   q int64/handle   p pointer
The guest side is an Alpha function per export that crosses one gate; the
host side casts the Alpha argument registers and calls Wine's real function.
Everything above the gate stays Alpha, which is the whole point.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

CTYPE = {'v': 'void', 'i': 'int', 'u': 'unsigned int', 'q': 'long long', 'p': 'void *'}
HOSTCAST = {'i': '(int)', 'u': '(unsigned)', 'q': '(void*)(uintptr_t)', 'p': '(void*)(uintptr_t)'}

SPECS = {
 'KERNEL32': ('k32', [
    "FindFirstFileA q p p", "FindNextFileA i q p", "FindClose i q",
    "GetFullPathNameA u p u p p", "GetFileAttributesA u p",
    "CreateFileA q p u u p u u q", "ReadFile i q p u p p",
    "SetFilePointer u q i p u", "GetFileSize u q p", "CloseHandle i q",
    "CreateFileMappingA q q p u u u p", "MapViewOfFile p q u u u u",
    "UnmapViewOfFile i p", "GetFileInformationByHandle i q p",
    "GetFileType u q", "DeleteFileA i p", "GetTempPathA u u p",
    "GetShortPathNameA u p p u", "GetWindowsDirectoryA u p u",
    "GetSystemDirectoryA u p u", "ExpandEnvironmentStringsA u p p u",
    "GetDriveTypeA u p", "GetLogicalDrives u",
    "GlobalAlloc q u u", "GlobalLock p q", "GlobalUnlock i q", "LocalFree q q",
    "GetSystemTimeAsFileTime v p", "FileTimeToLocalFileTime i p p",
    "FileTimeToSystemTime i p p", "CompareFileTime i p p",
    "GetDateFormatA i u u p p p i", "GetTimeFormatA i u u p p p i",
    "FormatMessageA u u p u u p u p", "GetLocaleInfoA i u u p i",
    "GlobalMemoryStatus v p", "GetComputerNameA i p p",
 ]),
 'ADVAPI32': ('adv', [
    "RegOpenKeyA i q p p", "RegOpenKeyExA i q p u u p", "RegCloseKey i q",
    "RegQueryValueA i q p p p", "RegQueryValueExA i q p p p p p",
    "RegSetValueA i q p u p i", "RegEnumKeyA i q u p u",
    "RegEnumValueA i q u p p p p p p", "RegDeleteKeyA i q p",
    "GetUserNameA i p p",
 ]),
 'SHELL32': ('shl', [
    "ShellExecuteA q q p p p p i", "ShellExecuteExA i p",
    "SHGetPathFromIDListA i p p", "SHBrowseForFolderA q p", "SHGetMalloc i p",
 ]),
 'COMDLG32': ('cdg', [
    "GetOpenFileNameA i p", "GetSaveFileNameA i p", "CommDlgExtendedError u",
 ]),
 'COMCTL32': ('cc', [
    "ImageList_Draw i q i q i i u", "InitCommonControls v",
 ]),
}

# Everything depends.exe reaches for while painting its own list rows, plus
# the rest of the USER32/GDI32 surface it imports.  These extend the
# hand-written USER32/GDI32 rather than replacing them, so they are emitted
# without a DllMain of their own.
EXTRA = {
 'USER32X': ('gu2', 'user32x_gen.c', [
    "CloseClipboard i", "CopyRect i p p", "DrawFocusRect i q p",
    "EmptyClipboard i", "EnableMenuItem i q u u", "EnableWindow i q i",
    "GetDC q q", "GetDlgItem q q i", "GetFocus q", "GetMessagePos u",
    "GetMessageTime i", "GetParent q q", "GetSubMenu q q i",
    "GetSysColor u i", "GetWindowRect i q p", "GetWindowTextA i q p i",
    "GetWindowTextLengthA i q", "IsIconic i q", "IsWindow i q",
    "IsWindowEnabled i q", "IsZoomed i q", "MessageBeep i u",
    "OpenClipboard i q", "ReleaseDC i q q", "RemoveMenu i q u u",
    "ScreenToClient i q p", "SetClipboardData q u q", "SetFocus q q",
    "DrawMenuBar i q", "SetMenu i q q", "GetMenu q q",
    "WinHelpA i q p u q",
 ]),
 'GDI32X': ('gd2', 'gdi32x_gen.c', [
    "CreateFontIndirectA q p", "ExtTextOutA i q i i u p p u p",
    "GetCharWidthA i q u u p", "GetObjectA i q i p", "GetTextAlign u q",
    "GetTextExtentPoint32A i q p i p", "GetTextExtentPointA i q p i p",
    "SetTextAlign u q u",
 ]),
}

def gen(dllname, prefix, entries, guest_out, host_lines, table_lines, exports,
        dllmain=True):
    src = [f'/* {dllname.lower()}.dll for Windows AXP64 — generated thin stubs.',
           ' * Each export runs as Alpha code and crosses one gate to the host,',
           f' * which calls Wine\'s real {dllname.lower()}. */',
           'typedef unsigned int UINT; typedef unsigned int DWORD;',
           'typedef int BOOL; typedef long long LL; typedef void *PV;',
           '#define NULL ((void*)0)', '']
    for e in entries:
        parts = e.split()
        name, ret, args = parts[0], parts[1], parts[2:]
        gate = f'__{prefix}_{name}'
        params = ', '.join(f'{CTYPE[a]} a{i}' for i, a in enumerate(args)) or 'void'
        callargs = ', '.join(f'a{i}' for i in range(len(args)))
        rt = CTYPE[ret]
        src.append(f'extern {rt} {gate}({params});')
        if ret == 'v':
            src.append(f'{rt} {name}({params}) {{ {gate}({callargs}); }}')
        else:
            src.append(f'{rt} {name}({params}) {{ return {gate}({callargs}); }}')
        exports.setdefault(dllname, []).append(name)

        # host gate
        cast = ', '.join(f'{HOSTCAST[a]}A(c,{i})' for i, a in enumerate(args))
        if ret == 'v':
            host_lines.append(f'static void g_{prefix}_{name}(CPUAlpha*c){{ {name}({cast}); R(c,0); }}')
        else:
            host_lines.append(f'static void g_{prefix}_{name}(CPUAlpha*c)'
                              f'{{ R(c,(uint64_t)(long long){name}({cast})); }}')
        table_lines.append(f'    {{"{gate}",g_{prefix}_{name}}},')
    src.append('')
    if dllmain:
        src.append('int DllMain(void *i, unsigned r, void *v) { return 1; }')
    open(guest_out, 'w').write('\n'.join(src) + '\n')

def main():
    host_lines, table_lines, exports = [], [], {}
    for dll, (prefix, entries) in SPECS.items():
        gen(dll, prefix, entries,
            os.path.join(HERE, dll.lower() + '_gen.c'), host_lines, table_lines, exports)
    for dll, (prefix, fname, entries) in EXTRA.items():
        gen(dll, prefix, entries, os.path.join(HERE, fname),
            host_lines, table_lines, exports, dllmain=False)
    hdr = ['/* generated by genfwd.py — host gates forwarding to Wine */', '']
    hdr += host_lines
    hdr += ['', '#define GENERATED_FORWARDERS \\']
    hdr += [l + ' \\' for l in table_lines]
    hdr += ['    /* end */', '']
    open(os.path.join(HERE, '..', 'src', 'fwd_gen.h'), 'w').write('\n'.join(hdr) + '\n')
    gates = {}
    for dll, (prefix, entries) in SPECS.items():
        gates[dll] = [f'__{prefix}_' + e.split()[0] for e in entries]
    for dll, (prefix, fname, entries) in EXTRA.items():
        gates[dll] = [f'__{prefix}_' + e.split()[0] for e in entries]
    for dll, names in exports.items():
        with open(os.path.join(HERE, dll.lower() + '.exports'), 'w') as f:
            for n in names: f.write(n + '\n')
        with open(os.path.join(HERE, dll.lower() + '.gates'), 'w') as f:
            f.write(','.join(gates[dll]) + '\n')
        print(f'{dll}: {len(names)} exports')

if __name__ == '__main__':
    main()
