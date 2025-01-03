#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <WinSock2.h>
#include <openssl/ssl.h>

class SocketClient {
public:
    SocketClient(int port, const char* host);
    ~SocketClient();

    void sendRequest(const char* msg);

private:
    SOCKET sock;
    int port;
    const char* host;
    

    bool initializeWinsock();
    void createSocket();
    bool connectToServer();
    bool initializeSSL(const char* msg, std::string* file_path);
    void cleanup(SOCKET sock);
    void send_ssl_data(SSL *ssl, const char *data, int data_len);
};

#endif // CLIENT_H
