// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

// reference additional headers your program requires here

// easyhook
#include "easyhook.h"
#pragma comment(lib, "EasyHook32.lib")

#define DllExport extern "C" __declspec( dllexport )
DllExport void cmd();
void init();
void hook();