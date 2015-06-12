////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <EngineAPI.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (CreateThread,             0xCA2BD06B, "CreateThread");
FUNCTION (LocalAlloc,               0x4C0297FA, "LocalAlloc");
FUNCTION (LocalFree,                0x5CBAEAF6, "LocalFree");
FUNCTION (MultiByteToWideChar,      0xEF4AC4E4, "MultiByteToWideChar");
FUNCTION (OutputDebugStringW,       0x470D22D2, "OutputDebugStringW");
FUNCTION (Sleep,                    0xDB2D49B0, "Sleep");
FUNCTION (TerminateThread,          0xBD016F89, "TerminateThread");
FUNCTION (VirtualAllocEx,           0x6E1A959C, "VirtualAllocEx");
FUNCTION (VirtualFreeEx,            0xC3B4EB78, "VirtualFreeEx");
FUNCTION (VirtualProtectEx,         0x53D98756, "VirtualProtectEx");
FUNCTION (WideCharToMultiByte,      0xC1634AF9, "WideCharToMultiByte");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (SysAllocString,           0x3F6CD052, "SysAllocString");
FUNCTION (SysAllocStringLen,        0xA7A6ED0E, "SysAllocStringLen");
FUNCTION (SysFreeString,            0x9BFF9CBE, "SysFreeString");
FUNCTION (SysStringLen,             0xE6A09A41, "SysStringLen");
FUNCTION (SafeArrayCreate,          0x32DA2758, "SafeArrayCreate");
FUNCTION (SafeArrayDestroy,         0xE11676C3, "SafeArrayDestroy");
FUNCTION (SafeArrayAccessData,      0x9F266B8E, "SafeArrayAccessData");
FUNCTION (SafeArrayUnaccessData,    0xAB2BF222, "SafeArrayUnaccessData");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (RtlCompareMemory,         0x770DCEF6, "RtlCompareMemory");
FUNCTION (RtlFillMemory,            0xC930AF1B, "RtlFillMemory");
FUNCTION (RtlMoveMemory,            0xCF14E85B, "RtlMoveMemory");
FUNCTION (StringFormatW,            0x0A86F9F7, "_vsnwprintf");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
FUNCTION (WSAStartup,               0x3BFCEDCB, "WSAStartup");
FUNCTION (WSACleanup,               0x19BD2C47, "WSACleanup");
FUNCTION (SocketConnect,            0x60AAF9EC, "connect");
FUNCTION (SocketClose,              0x79C679E7, "closesocket");
FUNCTION (SocketCreate,             0x492F0B6E, "socket");
FUNCTION (SocketSend,               0xE97019A4, "send");
FUNCTION (SocketSetOption,          0xC055F2EC, "setsockopt");
FUNCTION (SocketSetOptionIO,        0xEDE29208, "ioctlsocket");
FUNCTION (SocketRecieve,            0xE71819B6, "recv");
FUNCTION (Htons,                    0xEB769C33, "htons");
FUNCTION (Htonl,                    0xEB769C2C, "htonl");

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID EngineAPI::Constructor()
{
    GetModuleTable(GetModule(MODULE_KERNEL),
                   (LPVOID) &fnCreateThread,
                   (LPVOID) &fnWideCharToMultiByte);
    GetModuleTable(GetModule(MODULE_NTDLL),
                   (LPVOID) &fnRtlCompareMemory,
                   (LPVOID) &fnStringFormatW);
    GetModuleTable(GetModule(MODULE_OLEAUT),
                   (LPVOID) &fnSysAllocString,
                   (LPVOID) &fnSafeArrayUnaccessData);
    GetModuleTable(GetModule(MODULE_WS32),
                   (LPVOID) &fnWSAStartup,
                   (LPVOID) &fnHtonl);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID EngineAPI::GetModuleTable(HMODULE hModule, LPVOID pBegin, LPVOID pEnd)
{
    PDWORD pAddress = (PDWORD) pBegin;
    DWORD dwNumber  = ((DWORD) pEnd - (DWORD) pBegin) / sizeof(DWORD) + 1;

    for (DWORD i = 0; i < dwNumber; ++i)
        pAddress[i] = (DWORD) GetFunction(hModule, pAddress[i]);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
HMODULE EngineAPI::GetModule(DWORD dwHash)
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
FARPROC EngineAPI::GetFunction(HMODULE hModule, DWORD dwHash)
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
DWORD EngineAPI::GetHash(LPCSTR szInput, BOOL isTransformed, DWORD dwValue)
{
    CHAR ppCharacter = (isTransformed
                        ? *szInput
                        : (*szInput >= 'a' && *szInput <= 'z' ? *szInput & 0xDF : *szInput));
    return ppCharacter == '\0' ? dwValue : GetHash(szInput + 1, isTransformed, TRANSFORM(dwValue, ppCharacter));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD EngineAPI::GetHash(LPCWSTR szwInput, BOOL isTransformed, DWORD dwValue)
{
    WCHAR ppCharacter = (isTransformed
                         ? *szwInput
                         : (*szwInput >= L'a' && *szwInput <= L'z' ? *szwInput & 0xDF : *szwInput));
    return ppCharacter == '\0' ? dwValue : GetHash(szwInput + 1, isTransformed, TRANSFORM(dwValue, ppCharacter));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID EngineAPI::StringFormatW(LPWSTR szwInput, LPCWSTR szwcFormat, ...)
{
    va_list vArguments;
    va_start(vArguments, szwcFormat);
    fnStringFormatW(szwInput, 2048, szwcFormat, vArguments);
    va_end(vArguments);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID EngineAPI::StringDebugW(LPCWSTR szwcFormat, ...)
{
    va_list vArguments;
    LPWSTR szBuffer = ALLOCATE_ARRAY(WCHAR, sizeof(WCHAR) * 0x800);

    //
    // Iterate over every parameter and create the buffer
    //
    va_start(vArguments, szwcFormat);
    fnStringFormatW(szBuffer, 2048, szwcFormat, vArguments);
    va_end(vArguments);
    fnOutputDebugStringW(szBuffer);

    //
    // Release the memory
    //
    FREE (szBuffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD EngineAPI::WideUnicodeToAscii(LPCWSTR szwcSource, LPSTR *szDestination, DWORD dwLen)
{
    DWORD iRequired = fnWideCharToMultiByte(CP_ACP, 0, szwcSource, dwLen, NULL, 0, 0, NULL);

    *szDestination = ALLOCATE_ARRAY(CHAR, iRequired);
    {
        fnWideCharToMultiByte(CP_UTF8, 0, szwcSource, dwLen, *szDestination, iRequired, 0, NULL);
    }
    return iRequired;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD EngineAPI::WideUnicodeFromAscii(LPCSTR szcSource, LPWSTR *szwDestination, DWORD dwLen)
{
    DWORD iRequired = fnMultiByteToWideChar(CP_ACP, 0, szcSource, dwLen, NULL, 0);

    *szwDestination = ALLOCATE_ARRAY(WCHAR, iRequired + 0x01);
    {
        fnMultiByteToWideChar(CP_ACP, 0, szcSource, dwLen, *szwDestination, iRequired);
        *((*szwDestination) + iRequired) = '\0';
    }
    return iRequired;
}