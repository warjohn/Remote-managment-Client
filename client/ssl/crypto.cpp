
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
    if (std::ifstream(file_path)) {
        //std::cout << "File already exists" << std::endl;
        return false; //file is not present
    } else {
        return true; //file is present
    }
}

std::string Crypto::getFilePath() { 
    return file_path;
}


void Crypto::generate_client_cert(const char* ca_cert_file) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY* client_pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (rsa == nullptr) {
        fprintf(stderr, "Ошибка при генерации RSA ключа\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    EVP_PKEY_assign_RSA(client_pkey, rsa);

    FILE* ca_cert_fp = fopen(ca_cert_file, "r");
    if (!ca_cert_fp) {
        perror("Ошибка при открытии CA сертификата");
        return;
    }
    X509* ca_cert = PEM_read_X509(ca_cert_fp, nullptr, nullptr, nullptr);
    fclose(ca_cert_fp);
    if (!ca_cert) {
        fprintf(stderr, "Ошибка при чтении CA сертификата\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    X509_REQ* req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Ошибка при создании запроса на сертификат\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    X509_REQ_set_version(req, 0);
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Client", -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, client_pkey);
    if (X509_REQ_sign(req, client_pkey, EVP_sha256()) <= 0) {
        fprintf(stderr, "Ошибка при подписи запроса сертификата\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    X509* new_cert = X509_new();
    if (!new_cert) {
        fprintf(stderr, "Ошибка при создании нового сертификата\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    X509_set_version(new_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(new_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(new_cert), 31536000L); // 1 год
    X509_set_subject_name(new_cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(new_cert, X509_get_subject_name(ca_cert)); 
    X509_set_pubkey(new_cert, client_pkey);
    if (X509_sign(new_cert, client_pkey, EVP_sha256()) <= 0) {
        fprintf(stderr, "Ошибка при подписании сертификата\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    FILE* cert_fp = fopen("clientKeys/client.crt", "w");
    if (!cert_fp) {
        perror("Ошибка при открытии client.crt для записи");
        return;
    }

    int result = PEM_write_X509(cert_fp, new_cert);
    if (result != 1) {
        fprintf(stderr, "Ошибка при записи сертификата в файл client.crt\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(cert_fp);

    FILE* key_fp = fopen("clientKeys/client.key", "w");
    if (!key_fp) {
        perror("Ошибка при открытии client.key для записи");
        return;
    }
    if (PEM_write_PrivateKey(key_fp, client_pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        fprintf(stderr, "Ошибка при записи приватного ключа в файл client.key\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(key_fp);

    // clear
    X509_REQ_free(req);
    X509_free(new_cert);
    EVP_PKEY_free(client_pkey);
    X509_free(ca_cert);

    ERR_free_strings();
}