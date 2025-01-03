#include <iostream>
#include <cstring>
#include <string>
#include "client/client.h"



int main() {

    int port = 2222;
    const char* host = "127.0.0.1";
    const char* msg = "new";

    SocketClient skclient(port, host);
    skclient.sendRequest(msg);

    return 0;

/*
    // Инициализация WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    // Инициализация OpenSSL
    initOpenSSL();

    // Создание контекста для клиента
    SSL_CTX* ctx = createClientContext();
    configureClientContext(ctx);

    // Создание сокета
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Настройка адреса сервера
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(2222); // Порт сервера
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0) { // IP-адрес сервера
        std::cerr << "Invalid address" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Подключение к серверу
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Создаем SSL-сессию
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)clientSocket);

    // Устанавливаем SSL-соединение
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connect failed." << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(clientSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return EXIT_FAILURE;
    }

    std::cout << "Connected with " << SSL_get_cipher(ssl) << " encryption." << std::endl;

    // Отправка данных

    const char* stop = "stop";
    char* input;
    while (true){
        std::cout << "Введите строку: ";
        std::cin >> *(input);
        if (*(input) == *(stop)){
            break;
        } else { 
            SSL_write(ssl, input, strlen(input));
        }
    }
    const char* request = "Hello, secure server!";
    SSL_write(ssl, request, strlen(request));

    // Чтение ответа
    char buffer[1024] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        std::cout << "Server response: " << buffer << std::endl;
    }

    // Завершение работы
    SSL_free(ssl);
    closesocket(clientSocket);
    SSL_CTX_free(ctx);

    // Очистка WinSock
    WSACleanup();
    return 0;
*/
}
