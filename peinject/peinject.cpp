// peinject.cpp : Inject pedump.dll to the process
//

#include "stdafx.h"

DllExport void load() {

	const char *dll = "pedump.dll";

	/*
	* Get process handle passing in the process ID.
	*/
	HANDLE process = GetCurrentProcess();
	if (process == NULL) {
		MessageBoxA(NULL, "Can not open process!", "peinject", MB_OK | MB_ICONEXCLAMATION);
	}

	/*
	 * Get address of the LoadLibrary function.
	 */
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		MessageBoxA(NULL, "Can not find LoadLibraryA", "peinject", MB_OK | MB_ICONEXCLAMATION);
	}

	/*
	 * Allocate new memory region inside the process's address space.
	 */
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		MessageBoxA(NULL, "Can not allocate memory", "peinject", MB_OK | MB_ICONEXCLAMATION);
	}

	/*
	 * Write the argument to LoadLibraryA to the process's newly allocated memory region.
	 */
	int n = WriteProcessMemory(process, arg, dll, strlen(dll), NULL);
	if (n == 0) {
		MessageBoxA(NULL, "Can not write to process memory", "peinject", MB_OK | MB_ICONEXCLAMATION);
	}

	/*
	 * Inject DLL into the process's address space.
	 */
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		MessageBoxA(NULL, "Can not create remote thread", "peinject", MB_OK | MB_ICONEXCLAMATION);
	}
	/*
	* Close the handle to the process
	*/
	CloseHandle(process);

}
