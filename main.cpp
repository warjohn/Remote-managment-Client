#include <iostream>
#include <cstring>
#include <string>
#include "client/client.h"


int main(int argc, char* argv[]) {

    int port = atoi(argv[1]);
    if (port <= 0) {
        std::cerr << "Error: Invalid port number." << std::endl;
        return 1; 
    }

    const char* host = "127.0.0.1";

    SocketClient skclient(port, host);
    while (true) {
        std::cout << "my_server: ";
        std::string msg_1;  
        std::getline(std::cin, msg_1);  
        skclient.sendRequest(msg_1.c_str()); 
    }
    return 0;

}
