/*
    Copyright (C) 2025 Dan Fruehauf <malkodan@gmail.com>.
    All rights reserved.

    This file is part of loopkb.

    loopkb is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    loopkb is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with loopkb.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>

// Basic function
typedef int (*socket_function_t)(int, int, int);
typedef int (*connect_function_t)(int, const struct sockaddr* addr, socklen_t addrlen);
typedef int (*accept_function_t)(int sockfd, struct sockaddr *restrict addr, socklen_t* restrict addrlen);
typedef int (*close_function_t)(int fd);
typedef int (*select_function_t)(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout);
typedef int (*pselect_function_t)(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask);

// send*
typedef ssize_t (*send_function_t)(int sockfd, const void* buf, size_t len, int flags);
typedef ssize_t (*sendto_function_t)(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*sendmsg_function_t)(int sockfd, const struct msghdr *msg, int flags);

// recv*
typedef ssize_t (*recv_function_t)(int sockfd, void* buf, size_t len, int flags);
typedef ssize_t (*recvfrom_function_t)(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t* restrict addrlen);
typedef ssize_t (*recvmsg_function_t)(int sockfd, struct msghdr *msg, int flags);

int _loopkb_banner(FILE* fp);

int _loopkb_socket(int domain, int type, int protocol);
int _loopkb_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _loopkb_accept(int sockfd, struct sockaddr *restrict addr, socklen_t* restrict addrlen);
int _loopkb_close(int fd);
int _loopkb_select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout);
int _loopkb_pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask);

ssize_t _loopkb_send(int sockfd, const void* buf, size_t len, int flags);
ssize_t _loopkb_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t _loopkb_sendmsg(int sockfd, const struct msghdr *msg, int flags);

ssize_t _loopkb_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t* restrict addrlen);
ssize_t _loopkb_recvmsg(int sockfd, struct msghdr *msg, int flags);

// Configuration variables
extern size_t loopkb_debug;
extern size_t loopkb_ring_size;
extern size_t loopkb_packet_size;
extern size_t loopkb_max_sockets;

// Override functions
extern socket_function_t _sys_socket;
extern connect_function_t _sys_connect;
extern accept_function_t _sys_accept;
extern close_function_t _sys_close;
extern select_function_t _sys_select;
extern pselect_function_t _sys_pselect;
extern send_function_t _sys_send;
extern sendto_function_t _sys_sendto;
extern sendmsg_function_t _sys_sendmsg;
extern recv_function_t _sys_recv;
extern recvfrom_function_t _sys_recvfrom;
extern recvmsg_function_t _sys_recvmsg;
