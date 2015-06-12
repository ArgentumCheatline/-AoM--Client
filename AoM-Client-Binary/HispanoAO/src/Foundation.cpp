////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Foundation/Foundation.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef VOID (WINAPI * ClsByteQueueWriteBlock)(LPVOID, SAFEARRAY **, DWORD, LPINT);
typedef VOID (WINAPI * ClsByteQueuePeekBlock)(LPVOID, SAFEARRAY **, DWORD, LPINT);
typedef VOID (WINAPI * ClsByteQueueLength)(LPVOID, LPINT);

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static ClsByteQueueLength     m_QueueLengthMethod;
static ClsByteQueueWriteBlock m_QueueWriteMethod;
static ClsByteQueuePeekBlock  m_QueuePeekMethod;
static LPVOID                *m_QueueRead, *m_QueueWrite;

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static TDetour m_RecvDetour;
static TDetour m_LoopDetour;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HELPER
////////////////////////////////////////////////////////////////////////////////////////////////////
INT WINAPI QueueLength(LPVOID lpQueue)
{
    INT iLen;
    m_QueueLengthMethod(lpQueue, &iLen);
    return iLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HELPER
////////////////////////////////////////////////////////////////////////////////////////////////////
INT WINAPI QueueWrite(LPVOID lpQueue, LPBYTE lpBuffer, DWORD dwLen)
{
    //!
    //! Create VB6 SAFE_ARRAY Bounds.
    //!
    SAFEARRAYBOUND stBound[1];
    stBound[0].lLbound   = 0x00;
    stBound[0].cElements = dwLen;

    //!
    //! Create VB6 SAFE_ARRAY.
    //!
    SAFEARRAY  *lpArray = fnSafeArrayCreate(VT_UI1, 0x01, stBound);

    BYTE HUGEP *lpByteArray;
    fnSafeArrayAccessData(lpArray, (void HUGEP**) &lpByteArray);
    fnRtlMoveMemory(lpByteArray, (LPVOID) lpBuffer, dwLen);
    fnSafeArrayUnaccessData(lpArray);

    //!
    //! Call the method.
    //!
    INT iLen;
    m_QueueWriteMethod(lpQueue, &lpArray, dwLen, &iLen);

    //!
    //! Destroy VB6 SAFE_ARRAY.
    //!
    fnSafeArrayDestroy(lpArray);
    return iLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HELPER
////////////////////////////////////////////////////////////////////////////////////////////////////
INT WINAPI QueuePeak(LPVOID lpQueue, LPBYTE lpBuffer, DWORD dwLen)
{
    //!
    //! Create VB6 SAFE_ARRAY Bounds.
    //!
    SAFEARRAYBOUND stBound[1];
    stBound[0].lLbound   = 0x00;
    stBound[0].cElements = dwLen;

    //!
    //! Create VB6 SAFE_ARRAY.
    //!
    SAFEARRAY *lpArray = fnSafeArrayCreate(VT_UI1, 0x01, stBound);

    //!
    //! Call the method.
    //!
    INT iLen;
    m_QueuePeekMethod(lpQueue, &lpArray, dwLen, &iLen);

    //!
    //! Copy from the SAFE_ARRAY to c-array.
    //!
    BYTE HUGEP *lpByteArray;
    fnSafeArrayAccessData(lpArray, (void HUGEP**) &lpByteArray);
    fnRtlMoveMemory((LPVOID) lpBuffer, lpByteArray, dwLen);
    fnSafeArrayUnaccessData(lpArray);

    //!
    //! Destroy VB6 SAFE_ARRAY.
    //!
    fnSafeArrayDestroy(lpArray);
    return iLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// TRAMPOLINE
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI OnRecvMessage()
{
    if (*m_QueueRead == NULL)
    {
        return;
    }
    INT iFirst = QueueLength(*m_QueueRead), iSecond = 0, iThird = 0;

    //!
    //! Retrieve the buffer of the messages.
    //!
    LPBYTE lpBuffer = ALLOCATE_ARRAY(BYTE, iFirst);
    QueuePeak(*m_QueueRead, lpBuffer, iFirst);

    //!
    //! Parse while there is data available.
    //!
    while (iFirst > 0)
    {        
        //!
        //! Call the method to parse the message.
        //!
        __asm CALL m_RecvDetour.lpTrampoline

        //!
        //! Read how many bytes has taken from the lastest handle.
        //!
        iSecond = iFirst - QueueLength(*m_QueueRead);
        iFirst  = iFirst - iSecond;

        //!
        //! Deferred to the engine.
        //!
        Engine::NetMessage(&lpBuffer[iThird], iSecond, MESSAGE_ID_SERVER);
        iThird += iSecond;
    }
    FREE(lpBuffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// TRAMPOLINE
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI OnLoop()
{
    if (*m_QueueWrite == NULL)
    {
        return;
    }

    INT iLen = QueueLength(*m_QueueWrite);
    if (iLen > 0)
    {
        LPBYTE lpBuffer = ALLOCATE_ARRAY(BYTE, iLen);
        QueuePeak(*m_QueueWrite, lpBuffer, iLen);

        //!
        //! Send the message to the buffer.
        //!
        Engine::NetMessage(lpBuffer, iLen, MESSAGE_ID_CLIENT);

        //!
        //! Deallocate the memory allocated.
        //!
        FREE(lpBuffer);
    }

    //!
    //! [CALL]
    //!
    Engine::NetHandle();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HOOK
////////////////////////////////////////////////////////////////////////////////////////////////////
GENERATE_METHOD_0F(HkRcvData, OnRecvMessage, m_RecvDetour.lpTrampoline);
GENERATE_METHOD_0F(HkLoop,    OnLoop,        m_LoopDetour.lpTrampoline);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnCreate()
{
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //! [GET] ClsByteQueue INSTANCE
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID lpRecvDataMethod = Memory::Find((LPVOID) 0x600000, 0x100000, 
            "\x8B\x35\xFF\xFF\xFF\xFF\x8D\x55\xB8\x52\x8D\x45\xE4\x8B\x0E\x6A\xFF\x50\x56",
            "xx????xxxxxxxxxxxxx");
    m_QueueRead  = (LPVOID *) *(LPDWORD)(((LPBYTE) lpRecvDataMethod) + 0x02);

    LPVOID lpSendDataMethod = Memory::Find((LPVOID) 0x600000, 0x100000, 
            "\xA1\xFF\xFF\xFF\xFF\x8B\x1D\xFF\xFF\xFF\xFF\x8D\x4D\xD8\x50\x51\xFF\xD3"
            "\x8B\x45\xD8\x8D\x4D\xE4",
            "x????xx????xxxxxxxxxxxxx");
    m_QueueWrite = (LPVOID *) *(LPDWORD)(((LPBYTE) lpSendDataMethod) + 0x01);

    EngineAPI::StringDebugW(L"[W][Memory] Write[0x%X] Read[0x%X]", 
        (DWORD) m_QueueWrite, 
        (DWORD) m_QueueRead);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    //! [GET] ClsByteQueue METHOD.
    ////////////////////////////////////////////////////////////////////////////////////////////////
    m_QueueLengthMethod = (ClsByteQueueLength) Memory::Backtrace(
        Memory::Find((LPVOID) 0x600000, 0x100000, 
            "\x53\x56\x57\x89\x65\xF4\xC7\x45\xF8\xFF\xFF\xFF\xFF"
            "\x33\xFF\x89\x7D\xFC\x8B\x75\x08\x56\x8B\x06\xFF\x50"
            "\x04\x8B\x4E\x3C",
            "xxxxxxxxx????xxxxxxxxxxxxxxxxx"));
    m_QueueWriteMethod  = (ClsByteQueueWriteBlock) Memory::Backtrace(
        Memory::Find((LPVOID) 0x600000, 0x100000, 
            "\x56\x8B\x06\xFF\x50\x04\x8B\x1D\xFF\xFF\xFF\xFF"
            "\x89\x7D\xE8\x89\x7D\xE4\x8B\x7D\x0C\x8B\x0F\x51"
            "\x6A\x01\xFF\xD3",
            "xxxxxxxx????xxxxxxxxxxxxxxxx"));
    m_QueuePeekMethod  = (ClsByteQueuePeekBlock) Memory::Backtrace(
        Memory::Find((LPVOID) 0x600000, 0x100000, 
            "\xFF\x50\x04\x8B\x45\x10\x89\x7D\xE8\x3B\xC7\x89"
            "\x7D\xE4\x7E\x18",
            "xxxxxxxxxxxxxxxx"));

    EngineAPI::StringDebugW(L"[W][Memory] .Length[0x%X] .Write[0x%X] .Peek[0x%X]", 
        (DWORD) m_QueueLengthMethod, 
        (DWORD) m_QueueWriteMethod,
        (DWORD) m_QueuePeekMethod);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    //! [DETOUR] Recv
    ////////////////////////////////////////////////////////////////////////////////////////////////
    TAction nAction;
    nAction.lpAddress   = (LPVOID) 0x600000;
    nAction.lpFunction  = (LPVOID) &HkRcvData;
    nAction.szwcPattern = "\xC7\x45\xFC\x16\x00\x00\x00\xE8\xFF\xFF\xFF\xFF"
                          "\xE9\xFF\xFF\xFF\xFF\xC7\x45\xFC\x17\x00\x00\x00\xB9"
                          "\x09\x00\x00\x00";
    nAction.szwcMask    = "xxxxxxxx????x????xxxxxxxxxxxx";
    LPVOID fnHandleIncomingMessages = Memory::MmWrite(nAction, &m_RecvDetour);

    //!
    //! Prevent recursive from happening.
    //!
    LPVOID lpRecursive = Memory::Find(fnHandleIncomingMessages, 
        0x100000,
        "\xE8\xFF\xFF\xFF\xFF\x68\xFF\xFF\xFF\xFF\xEB\x29"
        "\x8D\x4D\xCC\x51\x8D\x55\xD0",
        "x????x????xxxxxxxxx");
    Memory::MmHandleNop(lpRecursive, 0x05);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    //! [DETOUR] Loop
    ////////////////////////////////////////////////////////////////////////////////////////////////
    nAction.lpAddress   = (LPVOID) 0x600000;
    nAction.lpFunction  = (LPVOID) &HkLoop;
    nAction.szwcPattern = "\x8B\x45\xD8\x8D\x4D\xE4\x51\x50\x8B\x10\xFF\x92"
                          "\xAC\x00\x00\x00\x3B\xC7\xDB\xE2\x7D\x19\x8B\x55"
                          "\xD8\x8B\x35\xFF\xFF\xFF\xFF\x68\xAC\x00\x00\x00";
    nAction.szwcMask    = "xxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxx";
    Memory::MmWrite(nAction, &m_LoopDetour);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnDestroy()
{
    //!
    //! Erase all trampolines.
    //! 
    Memory::MmErase(m_RecvDetour);
    Memory::MmErase(m_LoopDetour);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnSend(LPCSTR szwData, DWORD dwLength)
{
    QueueWrite(*m_QueueWrite, (LPBYTE) szwData, dwLength);

    //!
    //! Handle the message premature.
    //!
    __asm CALL m_LoopDetour.lpTrampoline
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnReceive(LPCSTR szwData, DWORD dwLength)
{
    QueueWrite(*m_QueueRead, (LPBYTE) szwData, dwLength);

    //!
    //! Handle the message premature.
    //!
    __asm CALL m_RecvDetour.lpTrampoline
}