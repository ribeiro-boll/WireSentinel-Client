cmake_minimum_required(VERSION 3.16)
project(WireSentinel_Client C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(WireSentinel_Client
        include/jsonparser.h
        include/misc.h
        include/packet_list.h
        include/packet_service.h
        include/security.h
        include/services_table.h
        src/jsonparser.c
        src/main.c
        src/misc.c
        src/packet_list.c
        src/packet_service.c
        src/security.c
        src/buffer_list.c
        include/buffer_list.h)

target_link_libraries(WireSentinel_Client PRIVATE OpenSSL::Crypto Threads::Threads)