// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <psapi.h>


#include <detours.h>
#pragma comment(lib, "detours.lib")
#ifdef _WIN64
#pragma comment(lib, "Scylla_x64.lib")
#else
#pragma comment(lib, "Scylla_x86.lib")
#endif

#include <iostream>
#include <fstream>
