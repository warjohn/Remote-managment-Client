#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include "ssl/crypto.h"

class SocketClient {
public:
    SocketClient(int port, const char* host);
    ~SocketClient();

    void sendRequest(const char* msg);
    

private:
    SOCKET sock;
    int port;
    const char* host;
    SSL_CTX* ctx;    

    bool initializeWinsock();
    void createSocket();
    bool connectToServer();
    bool initializeSSL(const char* msg, std::string* file_path, Crypto crp);
    void cleanup(SOCKET sock);
    void send_ssl_data(SSL *ssl, const char *data, int data_len);
};

#endif // CLIENT_H
