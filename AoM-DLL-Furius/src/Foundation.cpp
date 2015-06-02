////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Foundation/Foundation.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static TDetour m_RecvDetour;
static TDetour m_SendDetour;
static TDetour m_LoopDetour;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// TRAMPOLINE
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI OnRecvMessage(BSTR szbMessage)
{
    Engine::NetMessage((LPBYTE) szbMessage, COM_SIZE(szbMessage) * 0x02, FALSE);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// TRAMPOLINE
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI OnSendMessage(BSTR *szbMessage)
{
    Engine::NetMessage((LPBYTE) *szbMessage, COM_SIZE(*szbMessage) * 0x02, TRUE);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// TRAMPOLINE
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI OnLoop()
{
    Engine::NetHandle();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// HOOK
////////////////////////////////////////////////////////////////////////////////////////////////////
GENERATE_METHOD_1F(HkRcvData,      OnRecvMessage,  m_RecvDetour.lpTrampoline);
GENERATE_METHOD_1F(HkSndData,      OnSendMessage,  m_SendDetour.lpTrampoline);
GENERATE_METHOD_0F(HkLoop,         OnLoop,         m_LoopDetour.lpTrampoline);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnCreate()
{
    //!
    //! [DETOUR] FuriusAO (Handle)
    //!
    TAction nAction;
    nAction.lpAddress   = (LPVOID) 0x600000;
    nAction.lpFunction  = (LPVOID) &HkRcvData;
    nAction.szwcPattern = "\x85\xC9\x74\x33\xC7\x45\xFC\x04\x00\x00\x00\x8B"
                          "\x95\x18\xFF\xFF\xFF\x52\xFF\x15\xFF\xFF\xFF\xFF"
                          "\x83\xE8\x01";
    nAction.szwcMask    = "xxxxxxxxxxxxxxxxxxxx????xxx";
    Memory::MmWrite(nAction, &m_RecvDetour);

    //!
    //! [DETOUR] FuriusAO (Send)
    //!
    nAction.lpAddress   = (LPVOID) 0x600000;
    nAction.lpFunction  = (LPVOID) &HkSndData;
    nAction.szwcPattern = "\x50\x68\xFF\xFF\xFF\xFF\xFF\x15\xFF\xFF\xFF\xFF"
                          "\x8B\xF8\x8B\x0D\xFF\xFF\xFF\xFF\xF7\xDF\x1B\xFF"
                          "\xF7\xDF\xF7\xDF";
    nAction.szwcMask    = "xx????xx????xxxx????xxxxxxxx";
    Memory::MmWrite(nAction, &m_SendDetour);

    //!
    //! [DETOUR] FuriusAO (Loop)
    //!
    nAction.lpAddress   = (LPVOID) 0x600000;
    nAction.lpFunction  = (LPVOID) &HkLoop;
    nAction.szwcPattern = "\xFF\x15\xFF\xFF\xFF\xFF\xE9\xFF\xFF\xFF\xFF\xC7"
                          "\x45\xFC\xAE\x01\x00\x00\x66\xC7\x05\xFF\xFF\xFF"
                          "\xFF\x00\x00\xC7\x45\xFC\xAF\x01\x00\x00";
    nAction.szwcMask    = "xx????x????xxxxxxxxxx????xxxxxxxxx";
    Memory::MmWrite(nAction, &m_LoopDetour, FALSE);
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
    Memory::MmErase(m_SendDetour);
    Memory::MmErase(m_LoopDetour);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnSend(LPCSTR szwData, DWORD dwLength)
{
    //!
    //! Allocate the packet
    //!
    BSTR sbMessage = COM_ALLOCATE_STRING((LPCWSTR) szwData);

    //!
    //! Send the packet
    //!
    ((VOID (WINAPI *)(BSTR *)) m_SendDetour.lpTrampoline)(&sbMessage);

    //!
    //! Free the packet
    //!
    COM_FREE(sbMessage);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Foundation::OnReceive(LPCSTR szwData, DWORD dwLength)
{
    //!
    //! Allocate the packet
    //!
    BSTR sbMessage = COM_ALLOCATE_STRING((LPCWSTR) szwData);

    //!
    //! Send the packet
    //!
    ((VOID (WINAPI *)(BSTR)) m_RecvDetour.lpTrampoline)(sbMessage);

    //!
    //! Free the packet
    //!
    COM_FREE(sbMessage);
}