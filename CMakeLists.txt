cmake_minimum_required(VERSION 3.5.0)
project(socket_client VERSION 0.1.0 LANGUAGES C CXX)

# Указываем путь к OpenSSL
set(OPENSSL_ROOT_DIR "C:/Users/Menar/source/C++/vcpkg/installed/x64-windows")
find_package(OpenSSL REQUIRED)

# Подключение заголовочных файлов
include_directories(C:/Users/Menar/source/C++/vcpkg/installed/x64-windows/include)
link_directories(C:/Users/Menar/source/C++/vcpkg/installed/x64-windows/lib)

# Создание исполнимого файла
add_executable(socket_client main.cpp)

# Линковка с OpenSSL
target_link_libraries(socket_client PRIVATE OpenSSL::SSL)
target_link_libraries(socket_client PRIVATE OpenSSL::Crypto)

# Линковка с другими библиотеками
target_link_libraries(socket_client PRIVATE fmt)
target_link_libraries(socket_client PRIVATE aws-cpp-sdk-core)

# Для aws-cpp-sdk-core может понадобиться добавить директории с заголовочными файлами
# target_include_directories(socket_client PRIVATE C:/path/to/aws-sdk/include)

# Установка флага кодировки UTF-8
add_compile_options("/utf-8")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")

# Тестирование
include(CTest)
enable_testing()
