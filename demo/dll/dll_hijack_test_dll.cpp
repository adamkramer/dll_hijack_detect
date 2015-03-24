/* Demo DLL, which once loaded will print a message to the user and then pause indefinitely (keeping the program running) */
#include "stdafx.h"
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		
		printf("DLL successfully loaded! Sleeping...");

		for (;;)
			Sleep(10000);

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
