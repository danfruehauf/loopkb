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

#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>

struct socket_info_t
{
	union
	{
		struct sockaddr addr_1;
		struct sockaddr_in6 addr6_1; // Largest member
		struct sockaddr_in addr4_1;
	};
	union
	{
		struct sockaddr addr_2;
		struct sockaddr_in6 addr6_2; // Largest member
		struct sockaddr_in addr4_2;
	};
	int protocol;
};

enum socket_type_t
{
	tcp_server = 0,
	tcp_client = 1,
	udp = 2,
	udp_initiator = 3,
	unknown = UINT8_MAX,
};

const char* _loopkb_nmq_generate_filename_for_socket(int sockfd, struct socket_info_t* socket_info, int type, char* buffer, size_t len);
char* _loopkb_nmq_inet_ntop(const struct sockaddr* addr, char* retval);
int _loopkb_nmq_socket(int sockfd, int domain, int type, int protocol);
int _loopkb_nmq_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _loopkb_nmq_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _loopkb_nmq_accept(int sockfd, const struct sockaddr *addr, socklen_t* addrlen, int flags);
int _loopkb_nmq_close(int fd);
ssize_t _loopkb_nmq_send(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t _loopkb_nmq_send_offload_stream(int index, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t _loopkb_nmq_send_offload_dgram(int index, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t _loopkb_nmq_receive(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
int _loopkb_nmq_select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout);
int _loopkb_nmq_pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask);
int _loopkb_nmq_ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask);
int _loopkb_nmq_fcntl64(int fd, int op, int arg);
void _loopkb_nmq_remove_offloaded_socket(int sockfd);

extern const size_t loopkb_offloaded_packet_payload_size;
