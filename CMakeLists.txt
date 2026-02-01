cmake_minimum_required(VERSION 3.20)
project(librevote)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)


add_library(librevote_crypto STATIC
        src/crypto/keypair.cpp
        src/crypto/keypair.h
        src/crypto/signature.cpp
        src/crypto/signature.h
        src/crypto/hash.cpp
        src/crypto/hash.h)

target_include_directories(librevote_crypto
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    PRIVATE 
        ${SODIUM_INCLUDE_DIRS})

target_link_libraries(librevote_crypto PRIVATE ${SODIUM_LIBRARIES})


add_library(librevote_network STATIC
        src/network/node_id.cpp
        src/network/node_id.h
        src/network/routing_table.cpp
        src/network/routing_table.h
        src/network/dht.cpp
        src/network/dht.h)

target_include_directories(librevote_network
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(librevote_network PUBLIC librevote_crypto)


add_library(librevote_votes STATIC
        src/votes/ballot.cpp
        src/votes/ballot.h
        src/votes/vote_storage.cpp
        src/votes/vote_storage.h)

target_include_directories(librevote_votes
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(librevote_votes PUBLIC librevote_crypto)


add_library(librevote_transport STATIC
        src/transport/udp_transport.cpp
        src/transport/udp_transport.h
        src/transport/p2p_node.cpp
        src/transport/p2p_node.h)

target_include_directories(librevote_transport
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(librevote_transport PUBLIC librevote_network)


add_executable(librevote main.cpp)

target_link_libraries(librevote PRIVATE 
    librevote_votes 
    librevote_transport
    librevote_network
    librevote_crypto)


enable_testing()
find_package(GTest REQUIRED)

add_executable(dht_test tests/dht_test.cpp)

target_include_directories(dht_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(dht_test PRIVATE
    librevote_network
    librevote_crypto
    GTest::gtest
    GTest::gtest_main)

add_test(NAME dht_test COMMAND dht_test)
