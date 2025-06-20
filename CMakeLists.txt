cmake_minimum_required(VERSION 3.13)

project(btt)

set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
add_executable(bitt
               src/bencode_utils.hpp
               src/tcp_client.hpp
               src/tracker_communication.hpp
               src/bencode_utils.cpp
               src/tcp_client.cpp
               src/bencode_utils.cpp
               src/tracker_communication.cpp
               src/main.cpp
               )

target_link_libraries(bitt PRIVATE OpenSSL::Crypto ws2_32)