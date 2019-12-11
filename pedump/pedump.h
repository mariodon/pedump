#pragma once
#include "stdafx.h"

void WINAPI GetSystemTimeAsFileTimeHook(LPFILETIME lpSystemTimeAsFileTime);
extern "C" __declspec(dllexport) void init();
extern "C" __declspec(dllexport) void cmd();

// Scylla Definitions
BOOL __stdcall ScyllaDumpCurrentProcessW(const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);
int __stdcall ScyllaIatSearch(DWORD dwProcessId, DWORD_PTR* iatStart, DWORD* iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
int __stdcall ScyllaIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR* dumpFile, const WCHAR* iatFixFile);
