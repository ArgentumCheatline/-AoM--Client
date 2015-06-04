////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Foundation/Foundation.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef VOID (WINAPI * ModProtocolHandleIncomingMessage)();
typedef VOID (WINAPI * ModProtocolFlushBuffer)();
typedef VOID (WINAPI * ClsByteQueueWriteBlock)(LPVOID, SAFEARRAY **, DWORD, LPINT);
typedef VOID (WINAPI * ClsByteQueuePeekBlock)(LPVOID, SAFEARRAY **, DWORD, LPINT);
typedef VOID (WINAPI * ClsByteQueueLength)(LPVOID, LPINT);

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static ClsByteQueueLength     m_QueueLengthMethod;
static ClsByteQueueWriteBlock m_QueueWriteMethod;
static ClsByteQueuePeekBlock  m_QueuePeekMethod;
static LPVOID                 m_QueueRead, m_QueueWrite;

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static TDetour m_HandleDetour, m_FlushDetour;

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
VOID WINAPI OnHandleMessage()
{
    INT iFirst = QueueLength(m_QueueRead), iSecond = 0, iThird = 0;

    //!
    //! Retrieve the buffer of the messages.
    //!
    LPBYTE lpBuffer = ALLOCATE_ARRAY(BYTE, iFirst);
    QueuePeak(m_QueueRead, lpBuffer, iFirst);

    //!
    //! Parse while there is data available.
    //!
    while (iFirst > 0)
    {
        //!
        //! Call the method to parse the message.
        //!
        ((ModProtocolHandleIncomingMessage) m_HandleDetour.lpTrampoline)();
        
        //!
        //! Read how many bytes has taken from the lastest handle.
        //!
        iSecond = iFirst - QueueLength(m_QueueRead);
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
VOID WINAPI OnHandleFlush()
{
    //!
    //! Retrieve the buffer of the messages.
    //!
    INT iLen     = QueueLength(m_QueueWrite);
    if (iLen > 0)
    {
        LPBYTE lpBuffer = ALLOCATE_ARRAY(BYTE, iLen);
        QueuePeak(m_QueueWrite, lpBuffer, iLen);

        //!
        //! Send the message to the buffer.
        //!
        Engine::NetMessage(lpBuffer, iLen, MESSAGE_ID_CLIENT);

        //!
        //! Deallocate the memory allocated.
        //!
        FREE(lpBuffer);
    }
    Engine::NetHandle();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HOOK
////////////////////////////////////////////////////////////////////////////////////////////////////
GENERATE_METHOD_0F(HkHandleMessage, OnHandleMessage, m_HandleDetour.lpTrampoline);
GENERATE_METHOD_0F(HkHandleFlush,   OnHandleFlush,   m_FlushDetour.lpTrampoline);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnCreate()
{
    //!
    //! [GET] Buffers
    //!
    LPVOID lpSendDataMethod = Memory::Find((LPVOID) 0x510000, 0x100000, 
            "\xFF\xD7\x66\x85\xF6\x74\x3E\xA1\xFF\xFF\xFF\xFF"
            "\x8D\x55\xA0\x52",
            "xxxxxxxx????xxxx");
    DWORD lpSendDataWriteBuffer = *(LPDWORD)(((LPBYTE) lpSendDataMethod) + 0x08);
    m_QueueWrite = (LPVOID) *(LPDWORD)(lpSendDataWriteBuffer);
    m_QueueRead  = (LPVOID) *(LPDWORD)(lpSendDataWriteBuffer - 0x04);

    //!
    //! [GET] ClsByteQueue methods.
    //!
    m_QueueLengthMethod = (ClsByteQueueLength) Memory::Backtrace(
        Memory::Find((LPVOID) 0x510000, 0x100000, 
            "\x53\x56\x57\x89\x65\xF4\xC7\x45\xF8\xFF\xFF\xFF\xFF"
            "\x33\xFF\x89\x7D\xFC\x8B\x75\x08\x56\x8B\x06\xFF\x50"
            "\x04\x8B\x4E\x3C",
            "xxxxxxxxx????xxxxxxxxxxxxxxxxx"));
    m_QueueWriteMethod  = (ClsByteQueueWriteBlock) Memory::Backtrace(
        Memory::Find((LPVOID) 0x510000, 0x100000, 
            "\x56\x8B\x06\xFF\x50\x04\x8B\x1D\xFF\xFF\xFF\xFF"
            "\x89\x7D\xE8\x89\x7D\xE4\x8B\x7D\x0C\x8B\x0F\x51"
            "\x6A\x01\xFF\xD3",
            "xxxxxxxx????xxxxxxxxxxxxxxxx"));
    m_QueuePeekMethod  = (ClsByteQueuePeekBlock) Memory::Backtrace(
        Memory::Find((LPVOID) 0x510000, 0x100000, 
            "\xFF\x50\x04\x8B\x45\x10\x89\x7D\xE8\x3B\xC7\x89"
            "\x7D\xE4\x7E\x18",
            "xxxxxxxxxxxxxxxx"));

    //!
    //! [DETOUR] MainAO (Handle)
    //!
    TAction nAction;
    nAction.lpAddress   = (LPVOID) 0x510000;
    nAction.lpFunction  = (LPVOID) &HkHandleMessage;
    nAction.szwcPattern = "\x50\x8B\x0D\xFF\xFF\xFF\xFF\x8B\x11\xA1\xFF\xFF"
                          "\xFF\xFF\x50\xFF\x52\x78\xDB\xE2\x89\x45\xBC\x83"
                          "\x7D\xBC\x00";
    nAction.szwcMask    = "xxx????xxx????xxxxxxxxxxxxx";
    LPVOID fnHandleIncomingMessages = Memory::MmWrite(nAction, &m_HandleDetour);

    //!
    //! Prevent recursive from happening in MainAO handle method.
    //!
    LPVOID lpRecursive = Memory::Find(fnHandleIncomingMessages, 
        0x10000,
        "\xE8\xFF\xFF\xFF\xFF\x68\xFF\xFF\xFF\xFF\xEB\x1D"
        "\x8D\x55\xD4\x52\x8D\x45\xD8",
        "x????x????xxxxxxxxx");
    Memory::MmHandleNop(lpRecursive, 0x05);

    //!
    //! [DETOUR] MainAO (Flush)
    //!
    nAction.lpAddress   = (LPVOID) 0x510000;
    nAction.lpFunction  = (LPVOID) &HkHandleFlush;
    nAction.szwcPattern = "\x8B\x45\xD8\x8D\x55\xE4\x52\x50\x8B\x08\xFF\x91"
                          "\xAC\x00\x00\x00\x3B\xC7\xDB\xE2\x7D\x11\x8B\x4D"
                          "\xD8\x68\xAC\x00\x00\x00";
    nAction.szwcMask    = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    Memory::MmWrite(nAction, &m_FlushDetour);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnDestroy()
{
   Memory::MmErase(m_HandleDetour);
   Memory::MmErase(m_FlushDetour);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnSend(LPCSTR szwData, DWORD dwLength)
{
    QueueWrite(m_QueueWrite, (LPBYTE) szwData, dwLength);

    //!
    //! Handle the message premature.
    //!
    ((ModProtocolFlushBuffer) m_FlushDetour.lpTrampoline)();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnReceive(LPCSTR szwData, DWORD dwLength)
{
    QueueWrite(m_QueueRead, (LPBYTE) szwData, dwLength);

    //!
    //! Handle the message premature.
    //!
    ((ModProtocolHandleIncomingMessage) m_HandleDetour.lpTrampoline)();
}