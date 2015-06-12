////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _ENGINE_MEMORY_HPP_
#define _ENGINE_MEMORY_HPP_

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Declarations
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <EngineAPI.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
/// STRUCTURE: Detour
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _TDetour
{
    LPVOID lpAddress;
    LPVOID lpTrampoline;
    DWORD  dwLength;
} TDetour;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// STRUCTURE: Action
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _TAction
{
    LPVOID  lpAddress;
    LPCSTR  szwcPattern;
    LPCSTR  szwcMask;
    LPVOID  lpFunction;
} TAction;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// MACRO: Assembly generation (PROCESSOR)
////////////////////////////////////////////////////////////////////////////////////////////////////
#define METHOD_EPILOGUE(X)                                              \
    __asm PUSH EBP                                                      \
    __asm MOV  EBP, ESP                                                 \
    __asm PUSHAD                                                        \
    __asm PUSHFD                                                        
#define METHOD_PROLOGUE(X)                                              \
    __asm POPFD                                                         \
    __asm POPAD                                                         \
    __asm MOV  ESP, EBP                                                 \
    __asm POP  EBP                                                      
                  
#define METHOD_JUMP(X)                                                  \
    __asm JMP X
#define METHOD_RETN(X)                                                  \
    __asm RETN X

////////////////////////////////////////////////////////////////////////////////////////////////////
/// MACRO: Stub generation for methods.
////////////////////////////////////////////////////////////////////////////////////////////////////
#define GENERATE_METHOD_0M(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name(LPVOID p0)                       \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }
#define GENERATE_METHOD_1M(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1)            \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }
#define GENERATE_METHOD_2M(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1, LPVOID p2) \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p2                                                   \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }
#define GENERATE_METHOD_0F(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name()                                \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }
#define GENERATE_METHOD_1F(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name(LPVOID p0)                       \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }
#define GENERATE_METHOD_2F(Name, Method, Trampoline)                    \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1)            \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_JUMP(Trampoline)                                         \
    }

////////////////////////////////////////////////////////////////////////////////////////////////////
/// MACRO: Stub generation for functions.
////////////////////////////////////////////////////////////////////////////////////////////////////
#define GENERATE_FUNCTION_0M(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name(LPVOID p0)                       \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x04)                                               \
    }
#define GENERATE_FUNCTION_1M(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1)            \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x08)                                               \
    }
#define GENERATE_FUNCTION_2M(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1, LPVOID p2) \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p2                                                   \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x0C)                                               \
    }
#define GENERATE_FUNCTION_0F(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name()                                \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x00)                                               \
    }
#define GENERATE_FUNCTION_1F(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name(LPVOID p0)                       \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x04)                                               \
    }
#define GENERATE_FUNCTION_2F(Name, Method)                              \
    __declspec(naked) VOID WINAPI Name(LPVOID p0, LPVOID p1)            \
    {                                                                   \
        METHOD_EPILOGUE(0)                                              \
        __asm PUSH p1                                                   \
        __asm PUSH p0                                                   \
        __asm CALL Method                                               \
        METHOD_PROLOGUE(0)                                              \
        METHOD_RETN(0x08)                                               \
    }

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Memory namespace
////////////////////////////////////////////////////////////////////////////////////////////////////
namespace Memory
{
    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Backtrace a function to its origin
    ///
    /// \param[in] lpAddress The address of the function body
    /// \return The origin of the function
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID Backtrace(LPVOID lpAddress);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Compare a memory given its pattern
    ///
    /// \param[in] lpAddress   The memory address
    /// \param[in] szwcPattern The bytes pattern
    /// \param[in] szwcMask    The bytes mask
    /// \return True or false
    ////////////////////////////////////////////////////////////////////////////////////////////////
    BOOL Compare(LPVOID lpAddress, LPCSTR szwcPattern, LPCSTR szwcMask);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Find a memory given a pattern
    ///
    /// \param[in] lpAddress   The start address
    /// \param[in] dwLimit     The limit size of the search
    /// \param[in] szwcPattern The bytes pattern
    /// \param[in] szwcMask    The bytes mask
    /// \return The start of memory with the given assembly pattern
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID Find(LPVOID lpAddress, DWORD dwLimit, LPCSTR szwcPattern, LPCSTR szwcMask);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Gets the offset of an address
    ///
    /// \param[in] lpAddress The memory address
    /// \return The real memory address
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID GetOffset(LPVOID lpAddress);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Return the size of the given opcode
    ///
    /// \param[in] lpAddress The memory address that contains the opcode
    /// \return The lenght of the opcode
    ////////////////////////////////////////////////////////////////////////////////////////////////
    DWORD GetSize(LPVOID lpAddress);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Gets the needed size for a detour
    ///
    /// \param[in] lpAddress     The memory address
    /// \param[in] dwRequirement The size needed by the detour
    /// \return The number of bytes needed
    ////////////////////////////////////////////////////////////////////////////////////////////////
    DWORD GetSize(LPVOID lpAddress, DWORD dwRequirement);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Erase a detour
    ///
    /// \param[in] pDetour The detour of the function detoured
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID MmErase(TDetour &pDetour);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Writes a detour
    ///
    /// \param[in]      pAction The action of the detour
    /// \param[out opt] pBuffer The buffer to store the memory
    /// \return The address of the function
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID MmWrite(TAction &pAction, TDetour *pBuffer);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Writes a detour
    ///
    /// \param[in]      pAction    The action of the detour
    /// \param[out opt] pBuffer    The buffer to store the memory
    /// \param[in]      bBacktrace True if should backtrace the method, false otherwise
    /// \return The address of the function
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID MmWrite(TAction &pAction, TDetour *pBuffer, BOOL bBacktrace);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Writes a detour
    ///
    /// \param[in]      lpAddress     The source to detour
    /// \param[in]      lpDestination The destination of the detour
    /// \param[out opt] pBuffer       The buffer to store the memory
    /// \return The trampoline address
    ////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID MmWrite(LPVOID lpAddress, LPVOID lpDestination, TDetour *pBuffer);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Writes an inconditional jump opcode.
    ///
    /// \param[in] lpSource      The memory address
    /// \param[in] lpDestination The destination of the jump
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID MmHandleJump(LPVOID lpSource, LPVOID lpDestination);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Writes nop opcodes.
    ///
    /// \param[in] lpSource The memory address
    /// \param[in] dwLength The number of bytes to nop
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID MmHandleNop(LPVOID lpSource, DWORD dwLength);
};

#endif // _ENGINE_MEMORY_HPP_