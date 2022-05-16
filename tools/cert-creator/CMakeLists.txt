# A simple CMake script for building the application.
cmake_minimum_required(VERSION 3.12.4)
project(cert_creation_tool)
set(OPENSSL_DIR "../../src/external/openssl/")
# Our only dependency is OpenSSL

include_directories(${OPENSSL_DIR}include)
include_directories(${OPENSSL_DIR})

add_executable(cert_creation_tool cert_creation_tool.cpp)
target_link_libraries(cert_creation_tool ssl)
target_link_libraries(cert_creation_tool crypto)
