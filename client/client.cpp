#include "client.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include "ssl/crypto.h"
#include <openssl/applink.c>
#include <fstream>
#include <string>

SocketClient::SocketClient(int port, const char* host) {
    this->port = port;
    this->host = host;
    std::cout << "Client is ready to connect with host - " << host << " and port - " << port << std::endl; 
}

SocketClient::~SocketClient() {
    shutdown(sock, SD_BOTH);
    closesocket(sock);  
    WSACleanup();  
    std::cout << "Client socket closed" << std::endl;
}

bool SocketClient::initializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << std::endl;
        return false;
    }
    return true;
}

void SocketClient::createSocket() {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
    }
}

bool SocketClient::connectToServer() {
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serverAddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return false;
    }
    return true;
}


void SocketClient::send_ssl_data(SSL *ssl, const char *data, int data_len) {
    int bytes_sent = 0;

    bytes_sent = SSL_write(ssl, data, data_len);

    if (bytes_sent <= 0) {
        int error_code = SSL_get_error(ssl, bytes_sent);
        std::cerr << "SSL_write error: " << error_code << std::endl;
    } else {
        std::cout << "Sent " << bytes_sent << " bytes." << std::endl;
    }
}
std::string receiveData(SSL* ssl) {
    char buffer[4096];
    std::vector<char> receivedData;
    int bytesReceived;

    while ((bytesReceived = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        receivedData.insert(receivedData.end(), buffer, buffer + bytesReceived);
        std::cout << "Received " << bytesReceived << " bytes." << std::endl;
    }
    
    receivedData.push_back('\0');
    return std::string(receivedData.begin(), receivedData.end() - 1);
}

bool writeServerData(std::string &message, std::string* file_path) {
    std::fstream file;
    file.open(*file_path, std::ios::out);
    if (!file) {
        std::cout << "Error in file creation" << std::endl;
        return false;
    } else {
        std::cout << "Create file" << std::endl;
        file << message;
        file.close();
        return true;
    }
}

bool SocketClient::initializeSSL(const char* msg, std::string* file_path, Crypto crp) {    
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "SSL_CTX creation failed." << std::endl;
        ERR_print_errors_fp(stderr); // Логирование ошибок OpenSSL
        return false;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connection failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        ERR_print_errors_fp(stderr); // Логирование ошибок OpenSSL
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    } else {
        std::cout << "SSL connection alright" << std::endl;
    }

    std::cout << "SSL connection established." << std::endl;

    send_ssl_data(ssl, msg, strlen(msg));

    std::string &serverMessage = receiveData(ssl);
    if (writeServerData(serverMessage, file_path)) {
        std::cout << "Process data - successfull" << std::endl; 
    } else {
        std::cout << "Process data - invalid" << std::endl;
    }

    const char* cstr = file_path->c_str(); 
    crp.generate_client_cert(cstr);


    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return true;
}

void SocketClient::cleanup(SOCKET sock) {
    closesocket(sock);
    WSACleanup();
}

void SocketClient::sendRequest(const char* msg) {
    Crypto crp;
    bool is_file = crp.getCert();
    std::string file_path = crp.getFilePath();
    if (is_file) {
        msg = "new";
        // Инициализация Winsock
        if (!initializeWinsock()) {
            return;
        }

        // Создание сокета
        createSocket();
        if (sock == INVALID_SOCKET) {
            return;
        }

        // Подключение к серверу
        if (!connectToServer()) {
            return;
        }

        // Инициализация OpenSSL
        if (!initializeSSL(msg, &file_path, crp)) {
            return;
        }

        // Очистка ресурсов
        cleanup(sock);
    } else {
        std::cout << "True" << std::endl;
        // Инициализация Winsock
        if (!initializeWinsock()) {
            return;
        }

        createSocket();
        if (sock == INVALID_SOCKET) {
            return;
        }
        // Инициализация OpenSSL
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        // Создание SSL_CTX
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            std::cerr << "SSL_CTX creation failed." << std::endl;
            ERR_print_errors_fp(stderr);
            return;
        }

        // Загрузка приватного и публичного ключей клиента
        const char* privateKeyPath = "clientKeys/client.key";  // Путь к приватному ключу
        const char* publicKeyPath = "clientKeys/client.crt";    // Путь к публичному ключу

        if (!SSL_CTX_use_certificate_file(ctx, publicKeyPath, SSL_FILETYPE_PEM)) {
            std::cerr << "Unable to load certificate." << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return;
        }

        if (!SSL_CTX_use_PrivateKey_file(ctx, privateKeyPath, SSL_FILETYPE_PEM)) {
            std::cerr << "Unable to load private key." << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return;
        }

        // Создание SSL-объекта и привязка его к сокету
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, (int)sock);

        // Установление SSL-соединения
        if (SSL_connect(ssl) <= 0) {
            int error_code = SSL_get_error(ssl, -1);
            std::cerr << "SSL connection failed: " << error_code << std::endl;
            ERR_print_errors_fp(stderr);
            return;
        } else {
            std::cout << "SSL connection established." << std::endl;
        }

        // Отправка "Hello, World!" серверу
        const char* msg = "Hello, World!";
        send_ssl_data(ssl, msg, strlen(msg));

        // Закрытие SSL-соединения
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);

        // Очистка ресурсов
        cleanup(sock);
    }
}
