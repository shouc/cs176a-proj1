cmake_minimum_required(VERSION 3.15)
project(socket C)

set(CMAKE_C_STANDARD 11)
add_executable(main main.c)

add_executable(tcp_client client_c_tcp.c)
add_executable(tcp_server server_c_tcp.c)

add_executable(udp_client client_c_udp.c)
add_executable(udp_server server_c_udp.c)
add_executable(udp_server_st udp_server_single_thread.c)
