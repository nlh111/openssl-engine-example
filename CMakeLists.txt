cmake_minimum_required(VERSION 3.18)
project(openssl)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
SET(CMAKE_CXX_STANDARD 17)

set(include_file 
"/usr/local/Cellar/openssl@3/3.1.3/include"
"/usr/local/include"
)
include_directories(${include_file})

set(lib_file
"/usr/local/Cellar/openssl@3/3.1.3/lib"
"/usr/local/lib"
)
link_directories(${lib_file})

set(lib libcrypto.3.dylib mbedtls mbedcrypto)

add_library(mbedtls_engine SHARED mbedtls_engine.cpp)
target_link_libraries(mbedtls_engine PRIVATE ${lib})

add_executable(ecdsa test.cpp mbedtls_engine.cpp)
target_link_libraries(ecdsa PRIVATE ${lib})