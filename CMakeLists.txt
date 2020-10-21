cmake_minimum_required(VERSION 3.15)
project(socket C)

set(CMAKE_C_STANDARD 11)
add_executable(main main.c)

add_executable(tcp_client tcp_client.c)
add_executable(tcp_server tcp_server.c)

add_executable(udp_client udp_client.c)
add_executable(udp_server udp_server.c)
add_executable(udp_server_mt udp_server_multithread.c)
