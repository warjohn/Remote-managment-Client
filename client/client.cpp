#include "client.h"
#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include "ssl/crypto.h"

SocketClient::SocketClient(int port, const char* host) {
    this->port = port;
    this->host = host;
    std::cout << "Client is ready to connect with host - " << host << " and port - " << port << std::endl; 
}

SocketClient::~SocketClient() {
    shutdown(clientSocket, SD_BOTH);
    closesocket(clientSocket);  
    WSACleanup();  
    std::cout << "Client socket closed" << std::endl;
}

void SocketClient::initWinSock() { 
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << std::endl;
        return;
    }
}

void SocketClient::initClientSock() {
    initWinSock();
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }
}

void SocketClient::settingsSocket() {
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port); 
    if (inet_pton(AF_INET, "localhost", &serverAddr.sin_addr) <= 0) { 
        std::cerr << "Invalid address" << std::endl;
        shutdown(clientSocket, SD_BOTH);
        WSACleanup();
        return;
    }
}

void SocketClient::connectSocket() {
    initWinSock();
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (connect((int)clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed with error: " << WSAGetLastError() << std::endl;
        shutdown(clientSocket, SD_BOTH);
        WSACleanup();
        return;
    }
}



void SocketClient::sendRequest() {
    Crypto crp;
    bool is_file = crp.getCert();
    
    if (is_file) { 
        std::cout << "is_file - \t " << is_file << std::endl;
        initClientSock();
        //settingsSocket();
        connectSocket();
    } else {

    }
}