cmake_minimum_required(VERSION 4.1)
project(librevote)

set(CMAKE_CXX_STANDARD 23)

add_library(crypto STATIC
        crypto/keypair.cpp
        crypto/keypair.h
        crypto/signature.cpp
        crypto/signature.h
        crypto/hash.cpp
        crypto/hash.h)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
target_include_directories(crypto PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(crypto PRIVATE ${SODIUM_LIBRARIES})