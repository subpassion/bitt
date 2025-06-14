cmake_minimum_required(VERSION 3.13)

project(btt)

set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
add_executable(bitt
               src/main.cpp
               src/bencode_utils.hpp
               src/bencode_utils.cpp)

target_link_libraries(bitt PRIVATE OpenSSL::Crypto)