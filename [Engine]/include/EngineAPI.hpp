////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _ENGINE_API_HPP_
#define _ENGINE_API_HPP_

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Declarations
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <ws2tcpip.h>
#include <Windows.h>
#include <Winternl.h>
#include <Tlhelp32.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Declarations
////////////////////////////////////////////////////////////////////////////////////////////////////
#define THIS_PROCESS (HANDLE) 0xFFFFFFFF

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Modules
////////////////////////////////////////////////////////////////////////////////////////////////////
#define MODULE_KERNEL   0x6E2BCA17
#define MODULE_NTDLL    0xAD74DBF2
#define MODULE_OLEAUT   0x21536419
#define MODULE_WS32     0x32E1EFA6

////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory manager
////////////////////////////////////////////////////////////////////////////////////////////////////
#define ALLOCATE(Type)              (Type *)  fnLocalAlloc(LPTR, sizeof(Type));
#define ALLOCATE_ARRAY(Type, Size)  (Type *)  fnLocalAlloc(LPTR, sizeof(Type) * Size);
#define FREE(Pointer)            if (Pointer) fnLocalFree(Pointer);
#define MEMSET(Pointer, Value, Size)          fnRtlFillMemory(Pointer, Size, Value)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory manager (UNICODE)
////////////////////////////////////////////////////////////////////////////////////////////////////
#define COM_SIZE(Source)            fnSysStringLen(Source)
#define COM_FREE(Source)            fnSysFreeString(Source)
#define COM_ALLOCATE(Size)          fnSysAllocStringLen(NULL, Size)
#define COM_ALLOCATE_STRING(Source) fnSysAllocString(Source)
#define COM_COMPARE(Source, Type)   fnStringFindW(Source, Type)

////////////////////////////////////////////////////////////////////////////////////////////////////
/// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////
#define FUNCTION(Declaration, Hash, Name) Fn##Declaration fn##Declaration = (Fn##Declaration) Hash;
#define TRANSFORM(T, J)             (((T >> 0x0D) | (T << 0x13)) + J)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel32.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef BOOL    (WINAPI *FnFreeLibrary)(HMODULE);
typedef HLOCAL  (WINAPI *FnLocalAlloc)(UINT, SIZE_T);
typedef HLOCAL  (WINAPI *FnLocalFree)(HLOCAL);
typedef VOID    (WINAPI *FnOutputDebugStringW)(LPCWSTR);
typedef VOID    (WINAPI *FnMultiByteToWideChar)(UINT, DWORD, LPCSTR, INT, LPWSTR, INT);
typedef INT     (WINAPI *FnStringCompareW)(LPCWSTR, LPCWSTR);
typedef LPWSTR  (WINAPI *FnStringCopyW)(LPWSTR, LPWSTR);
typedef INT     (WINAPI *FnStringSizeW)(LPCWSTR);
typedef LPVOID  (WINAPI *FnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *FnVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *FnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef INT     (WINAPI *FnWideCharToMultiByte)(UINT, DWORD, LPCWSTR, INT, LPSTR, INT, LPCSTR, LPBOOL);

////////////////////////////////////////////////////////////////////////////////////////////////////
// OLEAUT.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef BSTR    (WINAPI *FnSysAllocString)(CONST OLECHAR *);
typedef BSTR    (WINAPI *FnSysAllocStringLen)(CONST OLECHAR *, UINT);
typedef VOID    (WINAPI *FnSysFreeString)(BSTR);
typedef UINT    (WINAPI *FnSysStringLen)(BSTR);
typedef SAFEARRAY* (WINAPI *FnSafeArrayCreate)(VARTYPE, UINT, SAFEARRAYBOUND*);
typedef HRESULT (WINAPI *FnSafeArrayDestroy)(SAFEARRAY *);
typedef HRESULT (WINAPI *FnSafeArrayAccessData)(SAFEARRAY *, void **);
typedef HRESULT (WINAPI *FnSafeArrayUnaccessData)(SAFEARRAY *);

////////////////////////////////////////////////////////////////////////////////////////////////////
// NTDLL.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef SIZE_T  (WINAPI *FnRtlCompareMemory)(const LPVOID, const LPVOID, SIZE_T);
typedef VOID    (WINAPI *FnRtlFillMemory)(VOID UNALIGNED *, SIZE_T, CHAR);
typedef VOID    (WINAPI *FnRtlMoveMemory)(PVOID, const PVOID, SIZE_T);
typedef INT     (       *FnStringFormatW)(LPWSTR, SIZE_T, LPCWSTR, ...);

////////////////////////////////////////////////////////////////////////////////////////////////////
// WS2_32.DLL [Definition]
////////////////////////////////////////////////////////////////////////////////////////////////////
typedef INT     (WSAAPI *FnWSAStartup)(WORD, LPWSADATA);
typedef INT     (WSAAPI *FnWSACleanup)(VOID);
typedef INT     (WSAAPI *FnSocketConnect)(SOCKET, struct sockaddr *, INT);
typedef INT     (WSAAPI *FnSocketClose)(SOCKET);
typedef SOCKET  (WSAAPI *FnSocketCreate)(INT, INT, INT);
typedef INT     (WSAAPI *FnSocketSend)(SOCKET, LPCSTR, INT, INT);
typedef INT     (WSAAPI *FnSocketSetOption)(SOCKET, INT, INT, INT *, INT);
typedef INT     (WSAAPI *FnSocketSetOptionIO)(SOCKET, LONG, u_long*);
typedef INT     (WSAAPI *FnSocketRecieve)(SOCKET, CHAR *, INT, INT);
typedef u_short (WSAAPI *FnHtons)(u_short);
typedef u_long  (WSAAPI *FnHtonl)(u_long);

////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel32.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnLocalAlloc                 fnLocalAlloc;
extern FnLocalFree                  fnLocalFree;
extern FnOutputDebugStringW         fnOutputDebugStringW;
extern FnMultiByteToWideChar        fnMultiByteToWideChar;
extern FnStringCopyW                fnStringCopyW;
extern FnStringSizeW                fnStringSizeW;
extern FnVirtualAllocEx             fnVirtualAllocEx;
extern FnVirtualFreeEx              fnVirtualFreeEx;
extern FnVirtualProtectEx           fnVirtualProtectEx;

////////////////////////////////////////////////////////////////////////////////////////////////////
// OLEAUT.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnSysAllocString             fnSysAllocString;
extern FnSysAllocStringLen          fnSysAllocStringLen;
extern FnSysFreeString              fnSysFreeString;
extern FnSysStringLen               fnSysStringLen;
extern FnSafeArrayCreate            fnSafeArrayCreate;
extern FnSafeArrayDestroy           fnSafeArrayDestroy;
extern FnSafeArrayAccessData        fnSafeArrayAccessData;
extern FnSafeArrayUnaccessData      fnSafeArrayUnaccessData;

////////////////////////////////////////////////////////////////////////////////////////////////////
// NTDLL.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnRtlCompareMemory           fnRtlCompareMemory;
extern FnRtlFillMemory              fnRtlFillMemory;
extern FnRtlMoveMemory              fnRtlMoveMemory;
extern FnStringFormatW              fnStringFormatW;

////////////////////////////////////////////////////////////////////////////////////////////////////
// WS2_32.DLL [Table]
////////////////////////////////////////////////////////////////////////////////////////////////////
extern FnWSAStartup                 fnWSAStartup;
extern FnWSACleanup                 fnWSACleanup;
extern FnSocketConnect              fnSocketConnect;
extern FnSocketClose                fnSocketClose;
extern FnSocketCreate               fnSocketCreate;
extern FnSocketSend                 fnSocketSend;
extern FnSocketSetOption            fnSocketSetOption;
extern FnSocketSetOptionIO          fnSocketSetOptionIO;
extern FnSocketRecieve              fnSocketRecieve;
extern FnHtons                      fnHtons;
extern FnHtonl                      fnHtonl;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// EngineAPI namespace
////////////////////////////////////////////////////////////////////////////////////////////////////
namespace EngineAPI
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

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Formats a string
    ///
    /// \param[out] szwInput   The source to populate
    /// \param[in]  szwcFormat The format of the string
    /// \param[in]  ....       Any number of arguments
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID StringFormatW(LPWSTR szwInput, LPCWSTR szwcFormat, ...);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Print a debug string
    ///
    /// \param[in] szwcFormat The format of the string
    /// \param     ....       Any number of arguments
    ////////////////////////////////////////////////////////////////////////////////////////////////
    VOID StringDebugW(LPCWSTR szwcFormat, ...);
};

#endif // _ENGINE_API_HPP_