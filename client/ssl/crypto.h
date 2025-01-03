#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/types.h>


class Crypto {
public:


    bool getCert();
    std::string getFilePath();

private:

    SSL_CTX* ctx;
    std::string file_path = "keys/ca.crt";

    void initOpenSSL();
    void createClientContext();
    void configureClientContext();

};

#endif // CRYPTO_H