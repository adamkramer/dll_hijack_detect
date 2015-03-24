/*  This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created by Adam Kramer [2015] - Email: adamkramer at hotmail dot com */


/* Various includes and libraries as required by the Windows API calls used */
#include "stdafx.h"
#include "windows.h"
#include "TlHelp32.h"
#include "Softpub.h"
#include "Shlwapi.h"

#pragma comment (lib, "wintrust")
#pragma comment (lib, "Shlwapi.lib")

/* Defines version number of this software */
#define VERSION_NUMBER "v1.0"

/* Enumerations used to categorise location and properties of DLLs */
enum DLL_STATUS { DLL_NOT_FOUND, DLL_FOUND_UNSIGNED, DLL_FOUND_SIGNED };
enum DLL_LOCATION { DLL_WINDOWS_DIRECTORY, DLL_WINDOWS_16BIT_DIRECTORY, DLL_SYSTEM_DIRECTORY, DLL_EXE_DIRECTORY, DLL_PATH_VARIABLE, DLL_NUMBER_POSSIBLE_LOCATIONS };

/* This function takes a full path and returns FALSE if the file is correctly signed (digital certificate) */
long is_signed(LPCWSTR wPath) {

	/* Building various data structures used as part of the query */
	LONG lStatus;
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = wPath;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;


	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);
	WinTrustData.pPolicyCallbackData = NULL;
	WinTrustData.pSIPClientData = NULL;
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwUIContext = 0;

	WinTrustData.pFile = &FileData;

	/* API call which identifies whether a file has been correctly signed */
	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	/* This function returns 0 if the file is correctly signed */
	return lStatus;
}

int _tmain(int argc, _TCHAR* argv[])
{

	/* Configuration option 'display where at least one library is unsigned only' */
	BOOL bUnsignedonly = FALSE;
	BOOL bVerbose = FALSE;

	/* Print welcome message */
	printf("dll_hijack_detect ");
	printf(VERSION_NUMBER);
	printf(" - Adam Kramer\n");

	/* Process arguements and display usage instructions */
	if (argc > 1)
	{
		for (int i = 1; i < argc; i++)
		{
			if (!_wcsicmp(argv[i], L"/unsigned"))
			{
				printf("Info: Unsigned only mode activated\n");
				bUnsignedonly = TRUE;
			}
			else if (!_wcsicmp(argv[i], L"/verbose"))
			{
				printf("Info: Verbose mode activated\n");
				bVerbose = TRUE;
			}
		}
	}
	else
	{
		printf("Usage: dll_hijack_detect.exe [/unsigned] [/verbose]\n\n");
		printf("Optional parameters:\n/unsigned - Only flags DLLs where at least one of them is unsigned\n\n");
		printf("/verbose - Show all where DLLs are found in multiple search order locations\nregardless of whether the one loaded is one of them (expect false positives!)\n\n");
	}

	/* Create strings of various system directories that can be used for DLL hijacking */

	/* Usually C:\Windows\System32 */
	WCHAR wSystemDirectory[MAX_PATH];
	GetSystemDirectory(wSystemDirectory, MAX_PATH);
	wcscat_s(wSystemDirectory, L"\\");

	/* Usually C:\Windows */
	WCHAR wWindowsDirectory[MAX_PATH];
	GetWindowsDirectory(wWindowsDirectory, MAX_PATH);
	wcscat_s(wWindowsDirectory, L"\\");

	/* Usually C:\Windows\System */
	WCHAR wSystemDirectory_16bit[MAX_PATH];
	GetWindowsDirectory(wSystemDirectory_16bit, MAX_PATH);
	wcscat_s(wSystemDirectory_16bit, L"\\System\\");

	/* Various directories delimitered by a semi-colon in the path environmental variable */
	WCHAR wPathVariable[32767];
	GetEnvironmentVariable(L"PATH", wPathVariable, 32767);

	/* Take a system snapshot of all running processes */
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	/* Ignore first process, this is usually 'SYSTEM' */
	Process32First(hSnapshot, &pEntry);

	/* For each process... */
	while (Process32Next(hSnapshot, &pEntry))
	{

		/* Take a snapshot of all the modules (i.e. DLLs) in the particular process */
		HANDLE mSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pEntry.th32ProcessID);

		/* If the handle is bad, skip an interation */
		if ((int)mSnapshot == -1)
			continue;

		MODULEENTRY32 mEntry;
		mEntry.dwSize = sizeof(MODULEENTRY32);

		/* First module is the executable file path */
		Module32First(mSnapshot, &mEntry);

		/* Create pointer to path to executable - wExePath */
		TCHAR* wExePath = mEntry.szExePath;

		/* Directory executable sits in  - wExeDirectory (Full path, minus filename (but with leading backslash )*/
		TCHAR wExeDirectory[MAX_PATH];
		wcscpy_s(wExeDirectory, mEntry.szExePath);
		TCHAR* wFinalSlash = wcsrchr(wExeDirectory, '\\');
		++wFinalSlash[1] = '\0';

		/* For each module... */
		while (Module32Next(mSnapshot, &mEntry))
		{

			/* DLL filename from full path (everything after the final backslash */
			TCHAR* pFilename = wcsrchr(mEntry.szExePath, '\\');
			pFilename++;

			/* DLL path without filename (but including final backslash) */
			TCHAR wDLLPath[MAX_PATH];
			wcscpy_s(wDLLPath, mEntry.szExePath);
			TCHAR* tFinalSlashDLLPath = wcsrchr(wDLLPath, '\\');
			tFinalSlashDLLPath[1] = '\0';

			/* Create array which will store result of search of various locations */
			DLL_STATUS dllSearch[DLL_NUMBER_POSSIBLE_LOCATIONS] = { DLL_NOT_FOUND };

			/* Identifies whether the loaded DLL was found in DLL search path */
			BOOL bFoundInDLLSearchPath = FALSE;

			/*************************************************
			  Begin searching where Windows searches for DLLs 
			  (possible hijack locations)
			 **************************************************/

			TCHAR tPathBeingChecked[MAX_PATH];

			/* Check whether DLL can be found in directory the file itself is in */
			wcscpy_s(tPathBeingChecked, wExeDirectory);
			wcscat_s(tPathBeingChecked, pFilename);

			/* Ignore SysWow64, otherwise you get a TON of matches */
			TCHAR tWow64Dir[MAX_PATH];
			wcscpy_s(tWow64Dir, wWindowsDirectory);
			wcscat_s(tWow64Dir, L"syswow64\\");

			if (PathFileExists(tPathBeingChecked) && !StrStrI(wExeDirectory, tWow64Dir))
			{
		
				if (!is_signed(tPathBeingChecked))
					dllSearch[DLL_EXE_DIRECTORY] = DLL_FOUND_SIGNED;
				else
					dllSearch[DLL_EXE_DIRECTORY] = DLL_FOUND_UNSIGNED;

				if (!_wcsicmp(wExePath, tPathBeingChecked))
					bFoundInDLLSearchPath = TRUE;
			}

			/* Check whether DLL can be found in Windows directory*/
			wcscpy_s(tPathBeingChecked, wWindowsDirectory);
			wcscat_s(tPathBeingChecked, pFilename);

			if (PathFileExists(tPathBeingChecked) && _wcsicmp(wWindowsDirectory, wExeDirectory))
			{
				if (!is_signed(tPathBeingChecked))
					dllSearch[DLL_WINDOWS_DIRECTORY] = DLL_FOUND_SIGNED;
				else
					dllSearch[DLL_WINDOWS_DIRECTORY] = DLL_FOUND_UNSIGNED;

				if (!_wcsicmp(wExePath, tPathBeingChecked))
					bFoundInDLLSearchPath = TRUE;
			}

			/* Check whether DLL can be found in System directory */
			wcscpy_s(tPathBeingChecked, wSystemDirectory);
			wcscat_s(tPathBeingChecked, pFilename);

			if (PathFileExists(tPathBeingChecked) && _wcsicmp(wSystemDirectory, wExeDirectory)) 
			{
				if (!is_signed(tPathBeingChecked))
					dllSearch[DLL_SYSTEM_DIRECTORY] = DLL_FOUND_SIGNED;
				else
					dllSearch[DLL_SYSTEM_DIRECTORY] = DLL_FOUND_UNSIGNED;

				if (!_wcsicmp(wExePath, tPathBeingChecked))
					bFoundInDLLSearchPath = TRUE;
			}

			/* Check whether DLL can be found in System (16 bit) directory */
			wcscpy_s(tPathBeingChecked, wSystemDirectory_16bit);
			wcscat_s(tPathBeingChecked, pFilename);

			if (PathFileExists(tPathBeingChecked) && _wcsicmp(wSystemDirectory_16bit, wExeDirectory))
			{
				if (!is_signed(tPathBeingChecked))
					dllSearch[DLL_WINDOWS_16BIT_DIRECTORY] = DLL_FOUND_SIGNED;
				else
					dllSearch[DLL_WINDOWS_16BIT_DIRECTORY] = DLL_FOUND_UNSIGNED;

				if (!_wcsicmp(wExePath, tPathBeingChecked))
					bFoundInDLLSearchPath = TRUE;
			}

			/* Check whether DLL can be found in any of the path directories */
			
			/* Used in wcstok_s */
			WCHAR* wNextToken = NULL;
	
			/* Begin splitting the path environmental variable by the semi-colon delimiter */
			
			/* Don't alter the original, we want this for the next iteration */
			WCHAR wPathVariable_WorkingCopy[32767];
			wcscpy_s(wPathVariable_WorkingCopy, wPathVariable);

			WCHAR* wSplitPath = wcstok_s(wPathVariable_WorkingCopy, L";", &wNextToken);

			/* This will store locations where relevant DLLs have been found for displaying */
			WCHAR wFoundinPath[32767] = L"";

			/* While there are more delimited objects in the path */
			while (wSplitPath != NULL)
			{

				/* Sometimes the paths we search elsewhere (i.e. C:\Windows or C:\Windows\System32)
				    Are also present in the path, the following code excludes if it's found there
					to avoid double counting when actually its the same location */

				/* Path we're currently checking including final backslash */
				TCHAR wSplitPath_check[MAX_PATH];
				wcscpy_s(wSplitPath_check, wSplitPath);

				/* Only append a final backslash if there isn't one there already */
				if (wSplitPath[(wcslen(wSplitPath) - 1)] != '\\')
					wcscat_s(wSplitPath_check, L"\\");

				/* Check it's not the windows directory (i.e. C:\Windows\)*/
				if (!_wcsicmp(wSplitPath_check, wWindowsDirectory))
				{
					wSplitPath = wcstok_s(NULL, L";", &wNextToken);
						continue;
				}

				/* Check it's not the system directory (i.e. C:\Windows\System32\)*/
				if (!_wcsicmp(wSplitPath_check, wSystemDirectory))
				{
					wSplitPath = wcstok_s(NULL, L";", &wNextToken);
						continue;
				}

				/* Check it's not the 16 bit System directory (i.e. C:\Windows\System\)*/
				if (!_wcsicmp(wSplitPath_check, wSystemDirectory_16bit))
				{
					wSplitPath = wcstok_s(NULL, L";", &wNextToken);
						continue;
				}

				/* Check it's not the path the actual executable file sits in */
				if (!_wcsicmp(wSplitPath_check, wExeDirectory))
				{
					wSplitPath = wcstok_s(NULL, L";", &wNextToken);
						continue;
				}

				/* Create variable which is full path to libary which is being checked */
				wcscpy_s(tPathBeingChecked, wSplitPath);

				/* Only append a final backslash if there isn't one there already */
				if (tPathBeingChecked[(wcslen(tPathBeingChecked) - 1)] != '\\')
					wcscat_s(tPathBeingChecked, L"\\");

				wcscat_s(tPathBeingChecked, pFilename);

				/* Check whether that file exists */
				if (PathFileExists(tPathBeingChecked))
				{
					
					/* Identifies whether the loaded DLL was found in the DLL search order path */
					if (!_wcsicmp(wExePath, tPathBeingChecked))
						bFoundInDLLSearchPath = TRUE;
				
					/* If it exists, check whether it is digitally signed */
					if (!is_signed(tPathBeingChecked))
					{
						/* Update the fact we've found one, and append to the results string */

						/* There may be more than one found from the path variable
						    In order for unsigned-only mode to work, we shouldn't
							overwrite if we've found an UNSIGNED one previously */

						if (dllSearch[DLL_PATH_VARIABLE] != DLL_FOUND_UNSIGNED)
							dllSearch[DLL_PATH_VARIABLE] = DLL_FOUND_SIGNED;

						wcscat_s(wFoundinPath, wSplitPath_check);
						wcscat_s(wFoundinPath, pFilename);
						wcscat_s(wFoundinPath, L" [SIGNED]\n\n");
					}
					else
					{
						/* Update the fact we've found one, and append to the results string */
						dllSearch[DLL_PATH_VARIABLE] = DLL_FOUND_UNSIGNED;

						wcscat_s(wFoundinPath, wSplitPath_check);
						wcscat_s(wFoundinPath, pFilename);
						wcscat_s(wFoundinPath, L" [UNSIGNED]\n\n");
					}
				}

				/* Move to next delimited item */
				wSplitPath = wcstok_s(NULL, L";", &wNextToken);
			}

			/**********************************/
			/* Post identification processing */
			/**********************************/

			/* Counters for how many unsigned and signed copies of this particular DLL we've found */
			int iUnsignedFound = 0;
			int iSignedFound = 0;

			/* For each of the possible locations, talley how many signed and unsigned we've found */
			for (int i = 0; i < DLL_NUMBER_POSSIBLE_LOCATIONS; i++)
				if (dllSearch[i] == DLL_FOUND_SIGNED)
					iSignedFound++;
				else if (dllSearch[i] == DLL_FOUND_UNSIGNED)
					iUnsignedFound++;


			/* If it's found in two or more places (or at least one is unsigned is /unsigned mode is active) */
			if ((bVerbose || bFoundInDLLSearchPath) && (bUnsignedonly && (iUnsignedFound > 0 || !(!is_signed(wExePath))) && ((iSignedFound + iUnsignedFound) > 1) || !bUnsignedonly && ((iSignedFound + iUnsignedFound) > 1)))
			{

				/* Inform user that the DLL was found in more than one location it could be loaded from */
				wprintf(L"\nInfo: Possible DLL hijack, in %s (PID: %d)\nDLL: %s has been found in multiple 'DLL search order' locations:\n\n", pEntry.szExeFile, pEntry.th32ProcessID, pFilename);

				/* Show the path to the actually loaded DLL */
				wprintf(L"Actual loaded DLL:\n%s", wExePath);

				if (!is_signed(wExePath))
					printf(" [SIGNED]\n\n");
				else
					printf(" [UNSIGNED]\n\n");

				/* If we have found a copy in the executable's directory, let the user know (and whether it was signed) */
				if (dllSearch[DLL_EXE_DIRECTORY] == DLL_FOUND_SIGNED)
					wprintf(L"Executable base directory:\n%s%s [SIGNED]\n\n", wExeDirectory, pFilename);
				else if (dllSearch[DLL_EXE_DIRECTORY] == DLL_FOUND_UNSIGNED)		
					wprintf(L"Executable base directory:\n%s%s [UNSIGNED]\n\n", wExeDirectory, pFilename);

				/* If we have found a copy in the Windows\System32 path, let the user know (and whether it was signed) */
				if (dllSearch[DLL_SYSTEM_DIRECTORY] == DLL_FOUND_SIGNED)
					wprintf(L"System directory:\n%s%s [SIGNED]\n\n", wSystemDirectory, pFilename);
				else if (dllSearch[DLL_SYSTEM_DIRECTORY] == DLL_FOUND_UNSIGNED)
					wprintf(L"System directory:\n%s%s [UNSIGNED]\n\n", wSystemDirectory, pFilename);

				/* If we have found a copy in the 16 bit System path, let the user know (and whether it was signed) */
				if (dllSearch[DLL_WINDOWS_16BIT_DIRECTORY] == DLL_FOUND_SIGNED)
					wprintf(L"System directory (16 bit):\n%s%s [SIGNED]\n\n", wSystemDirectory_16bit, pFilename);
				else if (dllSearch[DLL_WINDOWS_16BIT_DIRECTORY] == DLL_FOUND_UNSIGNED)
					wprintf(L"System directory (16 bit):\n%s%s [UNSIGNED]\n\n", wSystemDirectory_16bit, pFilename);

				/* If we have found a copy in the Windows path, let the user know (and whether it was signed) */
				if (dllSearch[DLL_WINDOWS_DIRECTORY] == DLL_FOUND_SIGNED)
					wprintf(L"Windows directory:\n%s%s [SIGNED]\n\n", wWindowsDirectory, pFilename);
				else if (dllSearch[DLL_WINDOWS_DIRECTORY] == DLL_FOUND_UNSIGNED)
					wprintf(L"Windows directory:\n%s%s [UNSIGNED]\n\n", wWindowsDirectory, pFilename);

				/* If we have found a copy in any of the path environmental variable locations , let the user know (and whether it was signed) */
				if (dllSearch[DLL_PATH_VARIABLE] != DLL_NOT_FOUND)
					wprintf(L"Path variable directory:\n%s", wFoundinPath);

				/* Seperate each entry with a line */
				printf("-------------------------------------------------------------------------------");

			}
		}
	}
}
