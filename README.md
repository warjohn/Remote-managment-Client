# SSL Client for Secure Communication

## Description

This project is a basic C++ SSL client that connects to a server using SSL (Secure Sockets Layer). Upon the first connection, the client receives the root certificate (CA) from the server, and the server generates its own key pair that will be used for secure communication in subsequent connections.

This client application is designed to work in conjunction with an SSL-enabled server. It establishes a secure connection and supports basic communication with the server. The client does not use a database and focuses only on connecting to the server and handling SSL encryption.

## Key Features

- **SSL-encrypted Communication**: The client establishes a secure SSL/TLS connection to the server for encrypted communication.
- **Root Certificate Reception**: Upon first connection, the client receives the server's root certificate (CA) to ensure the integrity and authenticity of the server.
- **Server Key Pair Generation**: The server generates its own public/private key pair during the first connection, which will be used for future communication.
- **Windows Compatibility**: This client is designed to run on Windows platforms.

## Requirements

To run this project on a Windows machine, you will need the following:

- **C++ compiler** (e.g., MinGW or Visual Studio).
- **OpenSSL**: A library for SSL/TLS support in C++.
- **SSL certificate**: The server will provide a root certificate (CA) upon first connection.

### Installing Dependencies

1. **OpenSSL**:
   - Download OpenSSL for Windows from [here](https://slproweb.com/products/Win32OpenSSL.html).
   - Make sure to install both the OpenSSL libraries and development files.
   - Add the OpenSSL `bin` directory to your system's `PATH` environment variable so that you can use the OpenSSL command-line tools.

2. **C++ Compiler**:
   - If you are using MinGW, you can download it from [here](https://sourceforge.net/projects/mingw/).
   - Alternatively, you can use **Visual Studio** (ensure to install the C++ development tools during installation).

## Installation Instructions

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/warjohn/Remote-managment-Client.git
  
