////////////////////////////////////////////////////////////////////////////////////////////////////
/// This file is subject to the terms and conditions defined in                                  ///
/// file 'LICENSE', which is part of this source code package.                                   ///
////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Foundation/Foundation.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static SOCKET m_Socket = NULL;
static HANDLE m_SocketReconnectThread = NULL;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// ENTRY-POINT-DLL
////////////////////////////////////////////////////////////////////////////////////////////////////
extern "C" BOOL WINAPI _DllMainCRTStartup(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            Engine::Constructor(hInstance);
            break;
        case DLL_PROCESS_DETACH:
            Engine::Destructor();
            break;
    }
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD WINAPI _ThreadNetwork(LPVOID lpParameter)
{
    while (TRUE)
    {
        //!
        //! Check if the socket requires to reconnect.
        //!
        if (m_Socket == NULL)
        {
            Engine::NetConnect();
        }
        //!
        //! Send alive socket message.
        //!
        else
        {
            Engine::NetMessage(NULL, 0x00, MESSAGE_ID_PING);
        }
        fnSleep(PROTOCOL_RECONNECT_TIME);
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::Constructor(HMODULE hModule)
{
    //!
    //! INIT: namespace EngineAPI
    //!
    EngineAPI::Constructor();

    //!
    //! INIT: WINSOCK_2_2
    //!
    WSADATA wsaData;
    fnWSAStartup(MAKEWORD(2, 2), &wsaData);
    
    m_SocketReconnectThread = fnCreateThread(NULL, 0, &_ThreadNetwork, NULL, 0, NULL);

    //!
    //! INIT: namespace Foundation
    //!
    Foundation::OnCreate();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::Destructor()
{
    //!
    //! DESTROY: Connection
    //!
    Engine::NetClose();

    //!
    //! DESTROY: namespace Foundation
    //!
    Foundation::OnDestroy();

    //!
    //! DESTROY: WINSOCK_2_2
    //!
    if (m_SocketReconnectThread != NULL)
    {
        fnTerminateThread(m_SocketReconnectThread, 0xFFFFFFFF);
    }
    fnWSACleanup();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::NetConnect()
{
    struct sockaddr_in lpServer;

    ///
    /// Set the HINT of the socket
    ///
    fnRtlFillMemory(&lpServer, sizeof(struct sockaddr_in), 0);
    lpServer.sin_family      = AF_INET;
    lpServer.sin_addr.s_addr = fnHtonl(INADDR_LOOPBACK);
    lpServer.sin_port        = fnHtons(PROTOCOL_PORT);

    ///
    /// Create the socket
    ///
    SOCKET hSocket = fnSocketCreate(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET) 
    {
        return;
    }

    ///
    /// Connect the socket to the stratum server
    ///
    if (fnSocketConnect(hSocket, (struct sockaddr*) &lpServer, sizeof(lpServer)) != 0) 
    {
        return;
    }

    ///
    /// NON_BLOCKING
    ///
    u_long iMode = 1;
    fnSocketSetOptionIO(hSocket, FIONBIO, &iMode);

    ///
    /// Set TCP_KEEP_ALIVE
    ///
    INT dwSocketFlag = 0x00000001;
    fnSocketSetOption(hSocket, SOL_SOCKET, SO_KEEPALIVE, &dwSocketFlag, sizeof(dwSocketFlag));
    fnSocketSetOption(hSocket, IPPROTO_TCP, TCP_NODELAY, &dwSocketFlag, sizeof(dwSocketFlag));

    ///
    /// Set TIMEOUT
    ///
    INT dwSocketTimeout = 5000;
    fnSocketSetOption(hSocket, SOL_SOCKET, SO_RCVTIMEO, &dwSocketTimeout, sizeof(dwSocketTimeout));
    fnSocketSetOption(hSocket, SOL_SOCKET, SO_SNDTIMEO, &dwSocketTimeout, sizeof(dwSocketTimeout));
    m_Socket = hSocket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::NetClose()
{
    if (m_Socket != NULL)
    {
        fnSocketClose(m_Socket);
    }
    m_Socket = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::NetMessage(LPBYTE pbBuffer, INT iLength, INT iType)
{
    if (m_Socket == NULL)
    {
        return;
    }

    //!
    //! Allocate memory for the message.
    //!
    LPSTR lpDestination = ALLOCATE_ARRAY(CHAR, iLength + 0x03);

    //!
    //! Build the message.
    //!
    lpDestination[0x00] = iType;
    lpDestination[0x01] = (BYTE)((iLength >> 0x08) & 0xFF);
    lpDestination[0x02] = (BYTE)(iLength & 0xFF);
    
    if (pbBuffer != NULL)
    {
        fnRtlMoveMemory(&lpDestination[0x03], pbBuffer, iLength);
    }
    
    if (fnSocketSend(m_Socket, lpDestination, iLength + 0x03, 0) == SOCKET_ERROR)
    {
        Engine::NetClose();
    }

    //!
    //! Free the allocated memory.
    //!
    FREE (lpDestination);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Engine::NetHandle()
{
    if (m_Socket == NULL)
    {
        return;
    }

    //!
    //! Allocate a buffer for the message.
    //!
    LPSTR lpBuffer = ALLOCATE_ARRAY(CHAR, 0x1024);
    {
        //!
        //! Read everything.
        //!
        while (TRUE)
        {
            u_long uArgument = 0;

            //!
            //! Stop if there is nothing to read.
            //!
            if (fnSocketSetOptionIO(m_Socket, FIONREAD, &uArgument) != 0 || uArgument == 0)
              break;

            //!
            //! Read ${uArgument} bytes from the buffer.
            //!
            INT iReadHeader = fnSocketRecieve(m_Socket, lpBuffer, uArgument, 0);
            if (iReadHeader <= 0)
            {
                Engine::NetClose();
                break;
            }

            INT iMessage = lpBuffer[0x00];
            if (iMessage == MESSAGE_ID_CLIENT)
            {
                Foundation::OnReceive(&lpBuffer[0x03], (lpBuffer[1] << 8) | lpBuffer[2]);
            }
            else if (iMessage == MESSAGE_ID_SERVER)
            {
                Foundation::OnSend(&lpBuffer[0x03], (lpBuffer[1] << 8) | lpBuffer[2]);
            }
        }
    }
    FREE(lpBuffer);
}