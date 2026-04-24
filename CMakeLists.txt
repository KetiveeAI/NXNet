cmake_minimum_required(VERSION 3.20)
project(NXNet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL QUIET openssl)
if(NOT OPENSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif()

# We might need CURL for networking module
find_package(CURL QUIET)

add_subdirectory(nxbase)
add_subdirectory(nxcrypto)
add_subdirectory(nxhttp)
add_subdirectory(networking)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/nxbase/include
    ${CMAKE_CURRENT_SOURCE_DIR}/nxbase
    ${CMAKE_CURRENT_SOURCE_DIR}/nxcrypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/nxcrypto
    ${CMAKE_CURRENT_SOURCE_DIR}/nxhttp/include
    ${CMAKE_CURRENT_SOURCE_DIR}/nxhttp
    ${CMAKE_CURRENT_SOURCE_DIR}/networking/include
    ${CMAKE_CURRENT_SOURCE_DIR}/networking
)
