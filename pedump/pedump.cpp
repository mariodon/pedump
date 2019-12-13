// pedump.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "pedump.h"

using namespace std;

HANDLE ProcessHandle;

// OEP hook for VC++
void WINAPI GetSystemTimeAsFileTimeHook(LPFILETIME lpSystemTimeAsFileTime)
{
	MessageBox(NULL, TEXT("Hooked GetSystemTimeAsFile"), TEXT("pedump"), MB_OK);
	cmd();
}


void dumpMemory(long long addr, size_t bytesToRead)
{
	char* buffer;
	buffer = new char[bytesToRead];
	memset(buffer, 0x0, bytesToRead);
	memcpy(buffer, (const void*)addr, bytesToRead);
	ofstream outfile;
	outfile.open("out.bin", ios::out | ios::binary);
	outfile.write(buffer, bytesToRead);
	outfile.close();
}

void queryMemory(long long start, long long end)
{
	long long current = start;
	while (current < end)
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery((LPCVOID)current, &mbi, sizeof(mbi));
		char thisLine[1000];
		sprintf_s(thisLine, "Start: %p, Size: %i, aBase: %p, BaseA: %p, State: %s Type: %s\n", (void*)current,
		          mbi.RegionSize, (void*)mbi.AllocationBase, (void*)mbi.BaseAddress,
		          mbi.State == MEM_FREE
			          ? "MEM_FREE"
			          : mbi.State == MEM_COMMIT
			          ? "MEM_COMMIT"
			          : mbi.State == MEM_RESERVE
			          ? "MEM_RESERVE"
			          : (const char*)mbi.State, mbi.Type == MEM_IMAGE
				                                    ? "MEM_IMAGE"
				                                    : mbi.Type == MEM_MAPPED
				                                    ? "MEM_MAPPED"
				                                    : mbi.Type == MEM_PRIVATE
				                                    ? "MEM_PRIVATE"
				                                    : (const char*)mbi.Type);
		cout << thisLine;
		current += mbi.RegionSize;
	}
}

DWORD getImageSize(HANDLE moduleHandle)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pImageHeader;
	pDosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
	pImageHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || (pImageHeader->Signature != IMAGE_NT_SIGNATURE))
	{
		cout << "Invalid PE header" << endl;
		return 0;
	}
	return pImageHeader->OptionalHeader.SizeOfImage;
}

void dumpModule()
{
	HMODULE hMods[1024];
	DWORD cbNeeded, ImageSize;
	unsigned int i;
	// Display list of Modules
	if (EnumProcessModules(ProcessHandle, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileName(hMods[i], szModName,
			                      sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				wcout << "Module " << i << ": " << szModName << "     Base Address:" << hMods[i] << endl;
			}
		}
	}

	// Select module
	cout << "Select a module to dump:" << endl;
	cin >> i;
	if (i > (cbNeeded / sizeof(HMODULE)))
	{
		cout << "Invalid module" << endl;
		return;
	}

	// Query PE header
	cout << "Base Address: " << hMods[i] << endl;
	ImageSize = getImageSize(hMods[i]);
	cout << "Image Size: " << hex << ImageSize << endl;
	if (ImageSize <= 0)
	{
		cout << "Invalid Image Size" << endl;
		return;
	}

	// Allocate cache memory
	char* dump;
	dump = new char[ImageSize];
	memset(dump, 0x0, ImageSize);
	memcpy(dump, (const void*)hMods[i], ImageSize);

	// Write dump file
	ofstream outfile;
	outfile.open("image.bin", ios::out | ios::binary);
	outfile.write(dump, ImageSize);
	outfile.close();
}

void init()
{
	MessageBox(NULL, TEXT("Initialized"), TEXT("pedump"), MB_OK);
	AllocConsole();
	// Setup stdin stdout redirects
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

	if (ProcessHandle = GetCurrentProcess())
	{
		cout << "Opened process" << endl;
	}
	else
	{
		cout << "Can not open process" << endl;
	}
}

extern "C" __declspec(dllexport) void cmd()
{
	while (true)
	{
		cout << "Select a command:" << endl;
		cout << "0 - Exit pedump" << endl;
		cout << "1 - Query Memory" << endl;
		cout << "2 - Dump Memory" << endl;
		cout << "3 - Dump Module" << endl;
		cout << "4 - Dump Executable and fix IAT" << endl;
		cout << "-1 - Exit Process" << endl;

		int command;
		cin >> command;
		switch (command)
		{
		case -1:
			ExitProcess(0);
			break;
		case 0:
			cout << "Exit pedump" << endl;
			return;
			break;
		case 1:
			cout << "Query memory:" << endl;
			long long start, end;
			cout << "Enter start address" << endl;
			cin >> start;
			cout << "Enter end address" << endl;
			cin >> end;
			queryMemory(start, end);
			break;
		case 2:
			cout << "Dump Process Memory:" << endl;
			long long addr;
			size_t bytesToRead;
			cout << "Enter address to read" << endl;
			cin >> addr;
			cout << "Enter bytes to read" << endl;
			cin >> bytesToRead;
			dumpMemory(addr, bytesToRead);
			break;
		case 3:
			dumpModule();
			break;
		case 4:
			// Fix OEP later
			if (!ScyllaDumpCurrentProcessW(0, (DWORD_PTR)GetModuleHandleA((LPCSTR)0), 0, L"dump.exe"))
			{
				cout << "Can not dump module" << endl;
			}
			cout << "Dumped module" << endl;

			{
				DWORD_PTR iatStart = 0;
				DWORD iatSize = 0;

				cout << "PID:" << GetCurrentProcessId() << endl;

				// Scan from base
				int error = ScyllaIatSearch(GetCurrentProcessId(), &iatStart, &iatSize,
				                            (DWORD_PTR)GetModuleHandleA((LPCSTR)0), TRUE);
				cout << "IAT search error: " << error << endl;
				cout << "IAT Start: " << iatStart << endl;
				cout << "IAT Size: " << iatSize << endl;

				error = ScyllaIatFixAutoW(iatStart, iatSize, GetCurrentProcessId(), L"dump.exe", L"dump.scy.exe");
				cout << "Dump fix error: " << error << endl;
				cout << "Fix completed" << endl;
			}

			break;
		default:
			cout << "Invalid command:" << endl;
			break;
		}
	}
}
		