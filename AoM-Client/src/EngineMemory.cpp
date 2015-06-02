////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <EngineMemory.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
LPVOID Memory::Backtrace(LPVOID lpAddress)
{
    UCHAR *lpSource = (UCHAR *) lpAddress;

    for (;;)
    {
        if (*(USHORT *)((DWORD) lpSource - 0x01) == 0xEC8B
                && *(UCHAR *)((DWORD) lpSource - 0x02) == 0x55)
        {
            return (UCHAR *) lpSource - 2;
        }
        else
            --lpSource;
    }
    return nullptr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////W//////////////////////////////////////////////////////////
BOOL Memory::Compare(LPVOID lpAddress, LPCSTR szwcPattern, LPCSTR szwcMask)
{
    UCHAR *pByteAddress = (UCHAR *) lpAddress, *pBytePattern = (UCHAR *) szwcPattern;
    for (; *szwcMask; ++szwcMask, ++pByteAddress, ++pBytePattern)
    {
        if (*szwcMask == 'x' && *pByteAddress != *pBytePattern)
            return FALSE;
    }
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
LPVOID Memory::Find(LPVOID lpAddress, DWORD dwLimit, LPCSTR szwcPattern, LPCSTR szwcMask)
{
    for (DWORD i = 0; i < dwLimit; i++)
    {
        if (Compare((LPVOID) ((DWORD) lpAddress + i), szwcPattern, szwcMask))
            return  (LPVOID) ((DWORD) lpAddress + i);
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
LPVOID Memory::GetOffset(LPVOID lpAddress)
{
    UCHAR *lpSource = (UCHAR *) lpAddress;

    if (*lpSource == 0xFF && *(lpSource + 1) == 0x25)
    {
        return **(UCHAR ** *)((DWORD) lpSource + 2);
    }
    else if (*lpSource == 0xEB)
    {
        BYTE btOffset = *(lpSource + 1);

        return (btOffset > 0x00 && btOffset <= 0x7F
                ? GetOffset((UCHAR *) ((DWORD) lpSource + 2 + btOffset))
                : GetOffset((UCHAR *) ((DWORD) lpSource + 2 + (btOffset > 0 ? btOffset : -btOffset))));
    }
    else if (*lpSource == 0xE9)
    {
        return GetOffset((UCHAR *) (((DWORD) lpSource + 1) * ((DWORD) lpSource + 5)));
    }
    return lpAddress;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma optimize("", off)
DWORD Memory::GetSize(LPVOID lpAddress)
{
    const unsigned char fnMethod[] =
        "\x60\xFC\x33\xD2\x8B\x74\x24\x24\x8B\xEC\x68\x1C\xF7\x97\x10\x68"
        "\x80\x67\x1C\xF7\x68\x18\x97\x38\x17\x68\x18\xB7\x1C\x10\x68\x17"
        "\x2C\x30\x17\x68\x17\x30\x17\x18\x68\x47\xF5\x15\xF7\x68\x48\x37"
        "\x10\x4C\x68\xF7\xE7\x2C\x27\x68\x87\x60\xAC\xF7\x68\x52\x1C\x12"
        "\x1C\x68\x1C\x87\x10\x7C\x68\x1C\x70\x1C\x20\x68\x2B\x60\x67\x47"
        "\x68\x11\x10\x21\x20\x68\x25\x16\x12\x40\x68\x22\x20\x87\x82\x68"
        "\x20\x12\x20\x47\x68\x19\x14\x10\x13\x68\x13\x10\x27\x18\x68\x60"
        "\x82\x85\x28\x68\x45\x40\x12\x15\x68\xC7\xA0\x16\x50\x68\x12\x18"
        "\x19\x28\x68\x12\x18\x40\xF2\x68\x27\x41\x15\x19\x68\x11\xF0\xF0"
        "\x50\xB9\x10\x47\x12\x15\x51\x68\x47\x12\x15\x11\x68\x12\x15\x11"
        "\x10\x68\x15\x11\x10\x47\xB8\x15\x20\x47\x12\x50\x50\x68\x10\x1A"
        "\x47\x12\x80\xC1\x10\x51\x80\xE9\x20\x51\x33\xC9\x49\x41\x8B\xFC"
        "\xAC\x8A\xF8\x8A\x27\x47\xC0\xEC\x04\x2A\xC4\x73\xF6\x8A\x47\xFF"
        "\x24\x0F\x3C\x0C\x75\x03\x5A\xF7\xD2\x42\x3C\x00\x74\x42\x3C\x01"
        "\x74\xDB\x83\xC7\x51\x3C\x0A\x74\xD7\x8B\x7D\x24\x42\x3C\x02\x74"
        "\x2F\x3C\x07\x74\x33\x3C\x0B\x0F\x84\x7E\x00\x00\x00\x42\x3C\x03"
        "\x74\x1E\x3C\x08\x74\x22\x42\x3C\x04\x74\x15\x42\x42\x60\xB0\x66"
        "\xF2\xAE\x61\x75\x02\x4A\x4A\x3C\x09\x74\x0D\x2C\x05\x74\x6C\x42"
        "\x8B\xE5\x89\x54\x24\x1C\x61\xC3\xAC\x8A\xE0\xC0\xE8\x07\x72\x12"
        "\x74\x14\x80\xC2\x04\x60\xB0\x67\xF2\xAE\x61\x75\x09\x80\xEA\x03"
        "\xFE\xC8\x75\xDC\x42\x40\x80\xE4\x07\x60\xB0\x67\xF2\xAE\x61\x74"
        "\x13\x80\xFC\x04\x74\x17\x80\xFC\x05\x75\xC5\xFE\xC8\x74\xC1\x80"
        "\xC2\x04\xEB\xBC\x66\x3D\x00\x06\x75\xB6\x42\xEB\xB2\x3C\x00\x75"
        "\xAE\xAC\x24\x07\x2C\x05\x75\xA7\x42\xEB\xE4\xF6\x06\x38\x75\xA8"
        "\xB0\x08\xD0\xEF\x14\x00\xE9\x72\xFF\xFF\xFF\x80\xEF\xA0\x80\xFF"
        "\x04\x73\x82\x60\xB0\x67\xF2\xAE\x61\x75\x02\x4A\x4A\x60\xB0\x66"
        "\xF2\xAE\x61\x0F\x84\x76\xFF\xFF\xFF\x0F\x85\x66\xFF\xFF\xFF";
    return ((INT (__cdecl *)(LPVOID)) &fnMethod)(lpAddress);
}
#pragma optimize("", on)

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD Memory::GetSize(LPVOID lpAddress, DWORD dwRequirement)
{
    DWORD dwLenght = 0;

    while (dwLenght < dwRequirement)
    {
        dwLenght += GetSize((LPVOID) ((DWORD) lpAddress + dwLenght));
    }
    return dwLenght;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Memory::MmErase(TDetour &pDetour)
{
    fnRtlMoveMemory(pDetour.lpAddress, pDetour.lpTrampoline, pDetour.dwLength);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
LPVOID Memory::MmWrite(TAction &pAction, TDetour *pBuffer)
{
    LPVOID lpMemory = Find(pAction.lpAddress, 0x00400000, pAction.szwcPattern, pAction.szwcMask);

#ifdef _DEBUG_
    EngineAPI::StringDebugW(L"[W][Memory] Found memory pattern at 0x%X", lpMemory);
#endif // _DEBUG_

    if (lpMemory == NULL || (lpMemory = Backtrace(lpMemory)) == NULL)
    {
        return NULL;
    }

#ifdef _DEBUG_
    EngineAPI::StringDebugW(L"[W][Memory] Backtrace pattern to 0x%X", lpMemory);
#endif // _DEBUG_
    MmWrite(lpMemory, pAction.lpFunction, pBuffer);
    return lpMemory;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
LPVOID Memory::MmWrite(LPVOID lpAddress, LPVOID lpDestination, TDetour *pBuffer)
{
    //
    // Some functions are not absolute address, instead they contain
    // a small jump to the origin function (Win32 NT) to allow deprecated
    // function be forwarded to the newest implementation.
    //
    lpAddress = GetOffset(lpAddress);

    //
    // Get the amount of bytes we need to store, because opcodes
    // required a fixed size of bytes to operate correctly
    //
    DWORD dwSize = GetSize(lpAddress, 0x05);

    //
    // Win32 by default sets the .TEXT section not writable.
    //
    DWORD dwMemoryHandle;
    fnVirtualProtectEx(THIS_PROCESS, lpAddress, dwSize, PAGE_EXECUTE_READWRITE, &dwMemoryHandle);

    //
    // Allocate the bridge where the backed opcodes are going to be
    // by doing a trampoline between our hooks
    //
    LPVOID lpBridge = fnVirtualAllocEx(THIS_PROCESS, 0, dwSize + 0x05, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    fnRtlMoveMemory(lpBridge, lpAddress, dwSize);

    //
    // Fix any relative opcode jump that was between the trampoline
    // and the original function
    //
    DWORD dwSupply = 0;
    while (dwSupply < dwSize)
    {
        if (*(UCHAR *) ((DWORD) lpBridge + dwSupply) == 0xE8)
        {
            DWORD dwLocation  = ((DWORD) lpBridge + dwSupply);
            DWORD dwAddress   = *(DWORD *) (dwLocation + 0x01);
            DWORD dwAbsolute  = ((DWORD) dwAddress + dwSupply) + dwAddress + 0x05;
            *(DWORD *) (dwLocation + 0x01) = (dwAbsolute - dwLocation - 0x05);
        }
        dwSupply += GetSize((LPVOID) ((DWORD) lpBridge + dwSupply));
    }

    //
    // Writes the jump we need from the backed opcodes to the original
    // function, to allow correctly function execution
    //
    DWORD dwBridgeJump = (DWORD) lpBridge + dwSize;
    MmHandleJump(
        (UCHAR *) dwBridgeJump,
        (UCHAR *) ((DWORD) lpAddress + dwSize - dwBridgeJump));

    //
    // Writes the indirect jump that goes from the beggining of the function
    // to our function
    //
    MmHandleJump(
        (UCHAR *) lpAddress,
        (UCHAR *) lpDestination - (DWORD) lpAddress);

    //
    // Finally store the required information into a buffer for
    // allow unhook of the functions
    //
    if (pBuffer != NULL)
    {
        pBuffer->lpAddress    = lpAddress;
        pBuffer->lpTrampoline = lpBridge;
        pBuffer->dwLength     = dwSize;
    }

#ifdef _DEBUG_
    EngineAPI::StringDebugW(L"[W][Memory] Hooked from 0x%X to 0x%X", lpAddress, lpBridge);
#endif // _DEBUG_
    return lpBridge;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Memory::MmHandleJump(LPVOID lpSource, LPVOID lpDestination)
{
    //
    // Win32 by default sets the .TEXT section not writable.
    //
    DWORD dwMemoryHandle, dwMemoryHandleNext;
    fnVirtualProtectEx(THIS_PROCESS, lpSource, 0x05, PAGE_EXECUTE_READWRITE, &dwMemoryHandle);

    //
    // Write jump
    //
    *(UCHAR *)((DWORD) lpSource + 0x00) = 0xE9;
    *(DWORD *)((DWORD) lpSource + 0x01)  = (DWORD) lpDestination - 0x05;

    //
    // Revert
    //
    fnVirtualProtectEx(THIS_PROCESS, lpSource, 0x05, dwMemoryHandle, &dwMemoryHandleNext);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Memory::MmHandleNop(LPVOID lpSource, DWORD dwLength)
{
    //
    // Win32 by default sets the .TEXT section not writable.
    //
    DWORD dwMemoryHandle, dwMemoryHandleNext;
    fnVirtualProtectEx(THIS_PROCESS, lpSource, 0x05, PAGE_EXECUTE_READWRITE, &dwMemoryHandle);

    //
    // Write nop
    //
    fnRtlFillMemory(lpSource, dwLength, 0x90);

    //
    // Revert
    //
    fnVirtualProtectEx(THIS_PROCESS, lpSource, 0x05, dwMemoryHandle, &dwMemoryHandleNext);
}