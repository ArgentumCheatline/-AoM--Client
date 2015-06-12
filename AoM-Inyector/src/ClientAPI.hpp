////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE.txt', which is part of this source code package.                               ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef __CLIENT_API_HPP_
#define __CLIENT_API_HPP_

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Declarations
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include <Winternl.h>
#include <Tlhelp32.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Modules
////////////////////////////////////////////////////////////////////////////////////////////////////
#define MODULE_KERNEL 0x6E2BCA17 

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Memory manager
////////////////////////////////////////////////////////////////////////////////////////////////////
#define ALLOCATE(Type)              (Type *)  fnLocalAlloc(LPTR, sizeof(Type));
#define ALLOCATE_ARRAY(Type, Size)  (Type *)  fnLocalAlloc(LPTR, sizeof(Type) * Size);
#define FREE(Pointer)            if (Pointer) fnLocalFree(Pointer);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////
#define FUNCTION(Declaration, Hash, Name) Fn##Declaration fn##Declaration = (Fn##Declaration) Hash;
#define TRANSFORM(T, J)             (((T >> 0x0D) | (T << 0x13)) + J)

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Kernel32.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef BOOL  (WINAPI * FnCloseHandle)(HANDLE);
typedef HANDLE(WINAPI * FnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL  (WINAPI * FnCreateProcessW)(LPCWSTR, LPCWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, 
    LPWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef VOID  (WINAPI * FnExitProcess)(UINT);
typedef LPWSTR(WINAPI * FnGetCommandLineW)(VOID);
typedef DWORD (WINAPI * FnGetCurrentDirectoryW)(DWORD, LPWSTR);
typedef BOOL  (WINAPI * FnGetThreadContext)(HANDLE, LPCONTEXT);
typedef HMODULE (WINAPI * FnLoadLibraryW)(LPCWSTR);
typedef HLOCAL(WINAPI * FnLocalAlloc)(UINT, SIZE_T);
typedef HLOCAL(WINAPI * FnLocalFree)(HLOCAL);
typedef HANDLE(WINAPI * FnOpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE(WINAPI * FnOpenThread)(DWORD, BOOL, DWORD);
typedef BOOL  (WINAPI * FnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL  (WINAPI * FnProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef DWORD (WINAPI * FnResumeThread)(HANDLE);
typedef VOID  (WINAPI * FnSleep)(DWORD);
typedef BOOL  (WINAPI * FnSetThreadContext)(HANDLE, const CONTEXT *);
typedef DWORD (WINAPI * FnSuspendThread)(HANDLE);
typedef LPSTR (WINAPI * FnStringCatW)(LPWSTR, LPWSTR);
typedef LPWSTR(WINAPI * FnStringCopyW)(LPWSTR, LPWSTR);
typedef INT   (WINAPI * FnStringSizeW)(LPCWSTR);
typedef BOOL  (WINAPI * FnThread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL  (WINAPI * FnThread32Next)(HANDLE, LPTHREADENTRY32);
typedef LPVOID(WINAPI * FnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL  (WINAPI * FnVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL  (WINAPI * FnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// SHELL32.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef LPWSTR * (WINAPI * FnCommandLineToArgvW)(LPCWSTR, INT *);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Kernel32.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnCloseHandle                fnCloseHandle;
extern FnCreateProcessW             fnCreateProcessW;
extern FnCreateToolhelp32Snapshot   fnCreateToolhelp32Snapshot;
extern FnExitProcess                fnExitProcess;
extern FnGetCommandLineW            fnGetCommandLineW;
extern FnGetCurrentDirectoryW       fnGetCurrentDirectoryW;
extern FnGetThreadContext           fnGetThreadContext;
extern FnLoadLibraryW               fnLoadLibraryW;
extern FnLocalAlloc                 fnLocalAlloc;
extern FnLocalFree                  fnLocalFree;
extern FnOpenProcess                fnOpenProcess;
extern FnOpenThread                 fnOpenThread;
extern FnProcess32First             fnProcess32First;
extern FnProcess32Next              fnProcess32Next;
extern FnResumeThread               fnResumeThread;
extern FnSleep                      fnSleep;
extern FnSetThreadContext           fnSetThreadContext;
extern FnSuspendThread              fnSuspendThread;
extern FnStringCatW                 fnStringCatW;
extern FnStringCopyW                fnStringCopyW;
extern FnStringSizeW                fnStringSizeW;
extern FnThread32First              fnThread32First;
extern FnThread32Next               fnThread32Next;
extern FnVirtualAllocEx             fnVirtualAllocEx;
extern FnVirtualFreeEx              fnVirtualFreeEx;
extern FnWriteProcessMemory         fnWriteProcessMemory;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Shell32.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnCommandLineToArgvW         fnCommandLineToArgvW;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// ClientAPI namespace
////////////////////////////////////////////////////////////////////////////////////////////////////
namespace ClientAPI
{
    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Initialise all tables
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID Constructor();

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Fill an entire table of procedures for the given module
    ///
    /// \param[in] hModule The base address of the module which contains the procedures
    /// \param[in] pBegin  The address of the first procedure in the table
    /// \param[in] pEnd    The address of the last procedure in the table
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID GetModuleTable(HMODULE hModule, LPVOID pBegin, LPVOID pEnd);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Retrieve the base address of a module given the name representation
    ///
    /// \param[in] dwHash The name representation of the module
    ///
    /// \return The base address of the module
    ////////////////////////////////////////////////////////////////////////////////////////////////
    HMODULE GetModule(DWORD dwHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Retrieve a function pointer to the given procedure
    ///
    /// \param[in] hModule The base address of the module which contains the procedure
    /// \param[in] dwHash  The name representation of the procedure
    ///
    /// \return The address of the procedure as a function pointer
    ////////////////////////////////////////////////////////////////////////////////////////////////
    FARPROC GetFunction(HMODULE hModule, DWORD dwHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Generates the hash representation of the given string
    ///
    /// \param[in] szwInput      The input string to be transformed
    /// \param[in] isTransformed TRUE if the string is already transformed
    /// \param[in] dwValue       The initial value of the transformation
    ///
    /// \return The hash representation of the given string
    ////////////////////////////////////////////////////////////////////////////////////////////////
    DWORD GetHash(LPCSTR szInput, BOOL isTransformed, DWORD dwValue = 0);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Generates the hash representation of the given unicode string
    ///
    /// \param[in] szwInput      The input unicode string to be transformed
    /// \param[in] isTransformed TRUE if the string is already transformed
    /// \param[in] dwValue       The initial value of the transformation
    ///
    /// \return The hash representation of the given unicode string
    ////////////////////////////////////////////////////////////////////////////////////////////////
    DWORD GetHash(LPCWSTR szwInput, BOOL isTransformed, DWORD dwValue = 0);
}

#endif // __CLIENT_API_HPP_