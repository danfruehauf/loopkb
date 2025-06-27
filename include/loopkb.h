#pragma once

#include <sys/socket.h>

// Basic function
typedef int (*socket_function_t)(int, int, int);
typedef int (*connect_function_t)(int, const struct sockaddr* addr, socklen_t addrlen);

// send*
typedef ssize_t (*send_function_t)(int sockfd, const void* buf, size_t len, int flags);
typedef ssize_t (*sendto_function_t)(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*sendmsg_function_t)(int sockfd, const struct msghdr *msg, int flags);

// recv*
typedef ssize_t (*recv_function_t)(int sockfd, void* buf, size_t len, int flags);
typedef ssize_t (*recvfrom_function_t)(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t *restrict addrlen);
typedef ssize_t (*recvmsg_function_t)(int sockfd, struct msghdr *msg, int flags);

int _loopkb_socket(int domain, int type, int protocol);
int _loopkb_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t _loopkb_send(int sockfd, const void* buf, size_t len, int flags);
ssize_t _loopkb_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t _loopkb_sendmsg(int sockfd, const struct msghdr *msg, int flags);

ssize_t _loopkb_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t *restrict addrlen);
ssize_t _loopkb_recvmsg(int sockfd, struct msghdr *msg, int flags);
