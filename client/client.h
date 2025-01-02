#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <WinSock2.h>

class SocketClient {
public:

    SocketClient(int port, const char* host);
    ~SocketClient();

    void sendRequest();

private:

    
    SOCKET clientSocket;
    int port;
    const char* host;

    void initWinSock();
    void initClientSock();
    void settingsSocket();
    void connectSocket();

};

#endif // CLIENT_H