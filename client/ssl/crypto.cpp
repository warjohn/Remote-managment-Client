
#include "crypto.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


void Crypto::initOpenSSL() { 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void Crypto::createClientContext() {
    const SSL_METHOD* method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void Crypto::configureClientContext() { 
    if (!SSL_CTX_load_verify_locations(ctx, file_path.c_str(), nullptr)) {
        std::cerr << "Failed to load CA certificate." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


bool Crypto::getCert() {
    std::ifstream iff(file_path);
    if (iff.bad() == true) {
        return false; //file is not present
    } else {
        return true; //file is present
    }
}

std::string Crypto::getFilePath() { 
    return file_path;
}