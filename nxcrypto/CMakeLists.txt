cmake_minimum_required(VERSION 3.16)
project(nxcrypto VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Backend option
option(NXCRYPTO_USE_OPENSSL "Use OpenSSL as TLS backend" OFF)
option(NXCRYPTO_USE_MBEDTLS "Use mbedTLS as TLS backend" OFF)

# Sources
set(NXCRYPTO_SOURCES
    hash.cpp
    base64.cpp
    tls.cpp
)

# Create library
add_library(nxcrypto STATIC ${NXCRYPTO_SOURCES})

target_include_directories(nxcrypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Backend linking
if(NXCRYPTO_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(nxcrypto OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(nxcrypto PRIVATE NXCRYPTO_OPENSSL)
elseif(NXCRYPTO_USE_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    target_link_libraries(nxcrypto mbedtls mbedcrypto mbedx509)
    target_compile_definitions(nxcrypto PRIVATE NXCRYPTO_MBEDTLS)
endif()

# Compiler warnings
target_compile_options(nxcrypto PRIVATE
    -Wall -Wextra -Wpedantic
)

# Install
install(TARGETS nxcrypto ARCHIVE DESTINATION lib)
install(FILES include/nxcrypto.h DESTINATION include)
