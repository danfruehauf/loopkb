#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/select.h>

#pragma once

int _loopkb_nmq_socket(int sockfd, int domain, int type, int protocol);
int _loopkb_nmq_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _loopkb_nmq_accept(int sockfd, const struct sockaddr *addr, socklen_t *addrlen);
int _loopkb_nmq_close(int fd);
ssize_t _loopkb_nmq_send(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t _loopkb_nmq_receive(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
int _loopkb_nmq_select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout);
