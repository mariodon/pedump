// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "pedump.h"

VOID (WINAPI* TrueGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime) = GetSystemTimeAsFileTime;
BOOL(WINAPI* TrueWriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	) = WriteFile;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DetourRestoreAfterWith();
		init();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueGetSystemTimeAsFileTime, GetSystemTimeAsFileTimeHook);
		// DetourAttach(&(PVOID&)TrueWriteFile, WriteFileHook);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueGetSystemTimeAsFileTime, GetSystemTimeAsFileTimeHook);
		// DetourDetach(&(PVOID&)TrueWriteFile, WriteFileHook);
		DetourTransactionCommit();
	}
	return TRUE;
}
