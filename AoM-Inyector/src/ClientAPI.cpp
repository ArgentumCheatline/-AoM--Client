////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE.txt', which is part of this source code package.                               ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include "ClientAPI.hpp"

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (CloseHandle,              0x0FFD97FB, "CloseHandle");
FUNCTION (CreateProcessW,           0x16B3FE88, "CreateProcessW");
FUNCTION (CreateToolhelp32Snapshot, 0xE454DFED, "CreateToolhelp32Snapshot");
FUNCTION (ExitProcess,              0x73E2D87E, "ExitProcess");
FUNCTION (GetCommandLineW,          0x36EF7386, "GetCommandLineW");
FUNCTION (GetCurrentDirectoryW,     0xBFC6EB65, "GetCurrentDirectoryW");
FUNCTION (GetThreadContext,         0x68A7C7D2, "GetThreadContext");
FUNCTION (LoadLibraryW,             0xEC0E4EA4, "LoadLibraryW");
FUNCTION (LocalAlloc,               0x4C0297FA, "LocalAlloc");
FUNCTION (LocalFree,                0x5CBAEAF6, "LocalFree");
FUNCTION (OpenProcess,              0xEFE297C0, "OpenProcess");
FUNCTION (OpenThread,               0x58C91E6F, "OpenThread");
FUNCTION (Process32First,           0x3249BAA7, "Process32First");
FUNCTION (Process32Next,            0x4776654A, "Process32Next");
FUNCTION (ResumeThread,             0x9E4A3F88, "ResumeThread");
FUNCTION (SetThreadContext,         0xE8A7C7D3, "SetThreadContext");
FUNCTION (SuspendThread,            0x0E8C2CDC, "SuspendThread");
FUNCTION (StringCatW,               0xCB734651, "lstrcatW");
FUNCTION (StringCopyW,              0xCB9B4A11, "lstrcpyW");
FUNCTION (StringSizeW,              0xDD434751, "lstrlenW");
FUNCTION (Thread32First,            0xB83BB6EA, "Thread32First");
FUNCTION (Thread32Next,             0x86FED608, "Thread32Next");
FUNCTION (VirtualAllocEx,           0x6E1A959C, "VirtualAllocEx");
FUNCTION (VirtualFreeEx,            0xC3B4EB78, "VirtualFreeEx");
FUNCTION (WriteProcessMemory,       0xD83D6AA1, "WriteProcessMemory");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (CommandLineToArgvW,       0xA8C03C08, "CommandLineToArgvW");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID ClientAPI::Constructor()
{
    GetModuleTable(GetModule(MODULE_KERNEL),
                   (LPVOID) &fnCloseHandle,
                   (LPVOID) &fnWriteProcessMemory);
    GetModuleTable(fnLoadLibraryW(L"shell32.dll"),
                   (LPVOID) &fnCommandLineToArgvW,
                   (LPVOID) &fnCommandLineToArgvW);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID ClientAPI::GetModuleTable(HMODULE hModule, LPVOID pBegin, LPVOID pEnd)
{
    PDWORD pAddress = (PDWORD) pBegin;
    DWORD dwNumber  = ((DWORD) pEnd - (DWORD) pBegin) / sizeof(DWORD) + 1;

    for (DWORD i = 0; i < dwNumber; ++i)
        pAddress[i] = (DWORD) GetFunction(hModule, pAddress[i]);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
HMODULE ClientAPI::GetModule(DWORD dwHash)
{
#if defined(_WIN64)
    PPEB pBlock = (PPEB) __readgsqword( 0x60 );
#else
    PPEB pBlock = (PPEB) __readfsdword( 0x30 );
#endif

    //
    // Get the pointer to the export module table
    // entry to query every module in it
    //
    PLIST_ENTRY pTable = &pBlock->Ldr->InMemoryOrderModuleList;

    //
    // Iterate over the MODULE_LIST to find
    // the desire module
    //
    for (PLIST_ENTRY pEntry = pTable->Flink; pEntry != pTable; pEntry = pEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pTableEntry = (PLDR_DATA_TABLE_ENTRY) pEntry;
        LPCWSTR szwName = pTableEntry->FullDllName.Buffer;

        if (GetHash(szwName, FALSE) == dwHash)
            return (HMODULE) pTableEntry->Reserved2[0];
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FARPROC ClientAPI::GetFunction(HMODULE hModule, DWORD dwHash)
{
    PIMAGE_DOS_HEADER pHeader
        = (PIMAGE_DOS_HEADER) hModule;
    PIMAGE_NT_HEADERS pExtHeader
        = (PIMAGE_NT_HEADERS)((DWORD) hModule + pHeader->e_lfanew);
    DWORD dwVirtualAddress
        = pExtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pDirectory = (PIMAGE_EXPORT_DIRECTORY) ((DWORD) hModule + dwVirtualAddress);

    //
    // Iterate over the EXPORT_FUNCTION_TABLE to find
    // for the target function using its hashed name
    //
    for (DWORD i = 0, j = pDirectory->NumberOfNames; i < j; ++i)
    {
        DWORD pAddress = (DWORD) hModule + (pDirectory->AddressOfNames + i * sizeof(DWORD));
        LPCSTR szName  = (LPCSTR) ((DWORD) hModule + (DWORD) (*(PDWORD) pAddress));

        if (dwHash != GetHash(szName, TRUE))
            continue;

        pAddress = pDirectory->AddressOfNameOrdinals + (i * sizeof(WORD));
        WORD wOrdinal = (WORD) (*(PDWORD) ((DWORD) hModule + pAddress));
        pAddress = pDirectory->AddressOfFunctions + (wOrdinal * sizeof(DWORD));
        pAddress = (DWORD) hModule + *((PDWORD) ((DWORD) hModule + pAddress));
        return (FARPROC) pAddress;
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD ClientAPI::GetHash(LPCSTR szInput, BOOL isTransformed, DWORD dwValue)
{
    CHAR ppCharacter = (isTransformed
                        ? *szInput
                        : (*szInput >= 'a' && *szInput <= 'z' ? *szInput & 0xDF : *szInput));
    return ppCharacter == '\0' ? dwValue : GetHash(szInput + 1, isTransformed, TRANSFORM(dwValue, ppCharacter));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD ClientAPI::GetHash(LPCWSTR szwInput, BOOL isTransformed, DWORD dwValue)
{
    WCHAR ppCharacter = (isTransformed
                         ? *szwInput
                         : (*szwInput >= L'a' && *szwInput <= L'z' ? *szwInput & 0xDF : *szwInput));
    return ppCharacter == '\0' ? dwValue : GetHash(szwInput + 1, isTransformed, TRANSFORM(dwValue, ppCharacter));
}
