////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE.txt', which is part of this source code package.                               ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Client.hpp"

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Client::Execute()
{
    ClientAPI::Constructor();

    //
    // Get the command line of the application
    //
    LPWSTR szwProcess  = ALLOCATE_ARRAY (WCHAR, MAX_PATH + 1);
    LPWSTR szwFilename = ALLOCATE_ARRAY (WCHAR, MAX_PATH + 1);
    BOOL   bIsLaunched = FALSE;
    GetCommandLine(szwProcess, szwFilename, &bIsLaunched);

    //
    // Contains the process and thread handle
    //
    HANDLE hProcess = NULL, hThread = NULL;
    if (bIsLaunched == TRUE)
    {
	    //
	    // Should the inyector also launch the application from a known state?
	    //
	    STARTUPINFOW pExecutionData;
	    PROCESS_INFORMATION pProcessData;
	    pExecutionData.cb = sizeof(pExecutionData);

	    //
	    // Attempt to load the specified target
	    //
	    if (!fnCreateProcessW(szwProcess, 
	    					  NULL, 
	    					  NULL, 
	    					  NULL, 
	    					  FALSE,
	                          INHERIT_CALLER_PRIORITY | CREATE_SUSPENDED, 
	                          NULL, 
	                          NULL, 
	                          &pExecutionData, 
	                          &pProcessData))
	    {
	        fnExitProcess(Error::IX_ERROR_PROCESS_NOT_FOUND);
	    }

	    hProcess = pProcessData.hProcess;
	    hThread  = pProcessData.hThread;
	}
	else
	{
	    //
	    // Get the Handle of the target process
	    //
	    DWORD dwUniqueID = GetProcess(ClientAPI::GetHash(szwProcess, FALSE));
	    if  (dwUniqueID == Error::IX_ERROR)
	    {
	        fnExitProcess(Error::IX_ERROR_PROCESS_NOT_FOUND);
	    }

	    //
	    // Open the target process for querying thread
	    //
	    hProcess = fnOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwUniqueID);
	    if (!hProcess)
	    {
	        fnExitProcess(Error::IX_ERROR_PROCESS_NOT_OPEN);
	    }

	    //
	    // Find available thread
	    //
	    DWORD dwThreadID = GetThread(dwUniqueID);
	    if  (dwThreadID == Error::IX_ERROR)
	    {
	        fnExitProcess(Error::IX_ERROR_THREAD_NOT_FOUND);
	    }

	    // Open the thread
	    hThread = fnOpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 
	    	FALSE, 
	    	dwThreadID);
	    if  (hThread == 0)
	    {
	        fnExitProcess(Error::IX_ERROR_THREAD_NOT_OPEN);
	    }
	    fnSuspendThread(hThread);
	}

	//
	// Execute the code
	//
    DWORD dwReturn = Execute(hProcess, hThread, szwFilename);

    //
    // Free allocated memory that was allocated when
    // requested from the Win32 command line
    //
    FREE (szwProcess);
    FREE (szwFilename);

    //
    // Exit process
    //
    fnExitProcess(dwReturn);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
Error Client::Execute(HANDLE hHandle, HANDLE hThread, LPCWSTR szwFilename)
{
    wchar_t szwFolder[128];
    CONTEXT pContext;

    //
    // Suspend Thread and get context
    //
    pContext.ContextFlags = CONTEXT_CONTROL;
    fnGetThreadContext(hThread, &pContext);

    //
    // Allocates memory for the name of the DLL
    //
    fnGetCurrentDirectoryW(sizeof(szwFolder) - 1, szwFolder);
    fnStringCatW(szwFolder, (wchar_t *) L"\\");
    fnStringCatW(szwFolder, (wchar_t *) szwFilename);

    //
    // Define a macro to allocate and copy string
    //
#define REMOTE_ALLOCATE(Type, Size) \
    LPVOID __##Type = fnVirtualAllocEx(hHandle, 0, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); \
    if (__##Type == NULL)                                                                                 \
    {                                                                                                     \
        return Error::IX_ERROR_PROCESS_NOT_ALLOCATED;                                                     \
    }                                                                                                     \
    else if (!fnWriteProcessMemory(hHandle, __##Type, Type, Size, 0))                                     \
    {                                                                                                     \
        return Error::IX_ERROR_PROCESS_NOT_WRITE;                                                         \
    }

    //
    // Copy the values
    //
    REMOTE_ALLOCATE (szwFolder, fnStringSizeW(szwFolder) * sizeof(WCHAR) + sizeof(WCHAR));

    //
    // The bytecode to inject to the remote process
    //
    const UCHAR pShellcode[] =
        "\x68\x00\x00\x00\x00"    // PUSH EIP
        "\x9C"                    // PUSHFD
        "\x60"                    // PUSHAD
        "\x68\x00\x00\x00\x00"    // PUSH NAME
        "\xB8\x00\x00\x00\x00"    // MOV EAX, LoadLibraryW
        "\xFF\xD0"                // CALL EAX
        "\x61"                    // POPAD
        "\x9D"                    // POPFD
        "\xC3";                   // RETN

    //
    // Build the shellcode.
    //
    *((PDWORD)((DWORD) pShellcode + 0x01)) = (DWORD) pContext.Eip;
    *((PDWORD)((DWORD) pShellcode + 0x08)) = (DWORD) __szwFolder;
    *((PDWORD)((DWORD) pShellcode + 0x0D)) = (DWORD) fnLoadLibraryW;

    //
    // Allocate the common code
    //
    REMOTE_ALLOCATE (pShellcode, sizeof(pShellcode));

    //
    // Restore the thread
    //
    pContext.Eip = (DWORD) __pShellcode;
    fnSetThreadContext(hThread, &pContext);
    fnResumeThread(hThread);
    return Error::IX_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Client::GetCommandLine(LPWSTR szwProcess, LPWSTR szwFilename, LPBOOL pbIsLaunched)
{
    INT iCount;
    LPWSTR *lpszwArguments = fnCommandLineToArgvW(fnGetCommandLineW(), &iCount);

    if (iCount >= ARGUMENT_COUNT)
    {
        fnStringCopyW(szwProcess, lpszwArguments[1]);
        fnStringCopyW(szwFilename, lpszwArguments[2]);

        if (iCount > ARGUMENT_COUNT)
        {
        	*pbIsLaunched = (lpszwArguments[3][0] == '1');
        }
        else
        {
        	*pbIsLaunched = FALSE;
        }
    }
    FREE (lpszwArguments);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD Client::GetThread(DWORD dwProcessID)
{
	HANDLE hHandle = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD  dwError = (DWORD) Error::IX_ERROR;

    if (hHandle != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 pEntry;
        pEntry.dwSize = sizeof(THREADENTRY32);

        if (fnThread32First(hHandle, &pEntry))
        {
            do
            {
                if (pEntry.th32OwnerProcessID == dwProcessID)
                    dwError = pEntry.th32ThreadID;
            }
            while (fnThread32Next(hHandle, &pEntry) && dwError == Error::IX_ERROR);
        }
        fnCloseHandle(hHandle);
    }
    return dwError;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD Client::GetProcess(DWORD dwProcessID)
{
    HANDLE hHandle = fnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD  dwError = (DWORD) Error::IX_ERROR;

    if (hHandle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pEntry;
        pEntry.dwSize = sizeof(PROCESSENTRY32);

        if (fnProcess32First(hHandle, &pEntry))
        {
            do
            {
                if (ClientAPI::GetHash(pEntry.szExeFile, FALSE) == dwProcessID)
                	dwError = pEntry.th32ProcessID;
            }
            while (fnProcess32Next(hHandle, &pEntry) && dwError == Error::IX_ERROR);
        }
        fnCloseHandle(hHandle);
    }
    return dwError;
}