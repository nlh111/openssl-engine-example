cmake_minimum_required(VERSION 3.18)
project(openssl)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

set(include_file 
"/usr/local/Cellar/openssl@3/3.1.3/include"
"/usr/local/include"
)
include_directories(${include_file})

set(lib_file
"/usr/local/Cellar/openssl@3/3.1.3/lib"
"/usr/local/lib"
${CMAKE_CURRENT_SOURCE_DIR}/build
)
link_directories(${lib_file})

set(lib libcrypto.3.dylib mbedtls mbedcrypto)

add_library(mbedtls_engine SHARED simple.c)
target_link_libraries(mbedtls_engine PRIVATE ${lib})

execute_process(COMMAND bash -c "openssl engine -t -c /Users/nlh/Desktop/openssl-engine-example/demo/build/libmbedtls_engine.dylib"  OUTPUT_VARIABLE output)
message("ls output: ${output}")