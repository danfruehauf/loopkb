#pragma once

#include <sys/socket.h>

typedef int (*socket_function_t)(int, int, int);
typedef int (*connect_function_t)(int, const struct sockaddr* addr, socklen_t addrlen);

int _loopkb_socket(int domain, int type, int protocol);
int _loopkb_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
