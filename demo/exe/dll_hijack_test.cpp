/* Demo vulnerable program which attempts to load a DLL without doing more checking beforehand! */

#include "stdafx.h"
#include "windows.h"

void _tmain(int argc, _TCHAR* argv[]) 
{ 
	LoadLibrary(L"dll_hijack_test_dll.dll"); 
}
