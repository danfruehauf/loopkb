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

#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "loopkb.h"
#include "nmq-backend.h"

#define VISIBILITY_DEFAULT __attribute__((__visibility__("default")))

size_t loopkb_debug = 0;
size_t loopkb_ring_size = 15;
size_t loopkb_packet_size = 1500;
size_t loopkb_max_sockets = 128;

socket_function_t _sys_socket = NULL;
connect_function_t _sys_connect = NULL;
accept_function_t _sys_accept = NULL;
close_function_t _sys_close = NULL;
select_function_t _sys_select = NULL;
pselect_function_t _sys_pselect = NULL;
send_function_t _sys_send = NULL;
sendto_function_t _sys_sendto = NULL;
sendmsg_function_t _sys_sendmsg = NULL;
recv_function_t _sys_recv = NULL;
recvfrom_function_t _sys_recvfrom = NULL;
recvmsg_function_t _sys_recvmsg = NULL;

// Normally for the dlsym line we would have:
// function_variable = (function_type) dlsym(RTLD_NEXT, #function_name);
// However, gcc -Wpedantic won't like it, so use this version that does the same, but silences it
#define OVERRIDE_FUNCTION(function_type, function_name, function_variable) \
	if (function_variable == NULL) \
	{ \
		*(void **) (&function_variable) = dlsym(RTLD_NEXT, #function_name); \
	} \

__attribute__((constructor))
static void _loopkb_init()
{
	loopkb_log_level_stdout = log_level_error;
	loopkb_log_level_stderr = log_level_error;

	if (getenv("LOOPKB_DEBUG") != NULL && strcmp(getenv("LOOPKB_DEBUG"), "1") == 0)
	{
		loopkb_debug = 1;
		loopkb_log_level_stdout = log_level_debug;
		loopkb_log_level_stderr = log_level_debug;
	}

	if (getenv("LOOPKB_RING_SIZE") != NULL)
	{
		loopkb_ring_size = atoi(getenv("LOOPKB_RING_SIZE"));
	}

	if (getenv("LOOPKB_PACKET_SIZE") != NULL)
	{
		loopkb_packet_size = atoi(getenv("LOOPKB_PACKET_SIZE"));
	}

	if (getenv("LOOPKB_MAX_SOCKETS") != NULL)
	{
		loopkb_packet_size = atoi(getenv("LOOPKB_MAX_SOCKETS"));
	}

	if (loopkb_debug > 0)
	{
		_loopkb_banner(stdout);
	}

	OVERRIDE_FUNCTION(socket_function_t, socket, _sys_socket);
	OVERRIDE_FUNCTION(connect_function_t, connect, _sys_connect);
	OVERRIDE_FUNCTION(accept_function_t, accept, _sys_accept);
	OVERRIDE_FUNCTION(close_function_t, close, _sys_close);
	OVERRIDE_FUNCTION(select_function_t, select, _sys_select);
	OVERRIDE_FUNCTION(pselect_function_t, pselect, _sys_pselect);
	OVERRIDE_FUNCTION(send_function_t, send, _sys_send);
	OVERRIDE_FUNCTION(sendto_function_t, sendto, _sys_sendto);
	OVERRIDE_FUNCTION(sendmsg_function_t, sendmsg, _sys_sendmsg);
	OVERRIDE_FUNCTION(recv_function_t, recv, _sys_recv);
	OVERRIDE_FUNCTION(recvfrom_function_t, recvfrom, _sys_recvfrom);
	OVERRIDE_FUNCTION(recvmsg_function_t, recvmsg, _sys_recvmsg);
}

int _loopkb_banner(FILE* fp)
{
	int column_width = 20;

	int retval = 0;
	retval += fprintf(fp, "============================\n");
	retval += fprintf(fp, "========== LoopKB ==========\n");
	retval += fprintf(fp, "============================\n");
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_DEBUG", column_width, loopkb_debug);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_RING_SIZE", column_width, loopkb_ring_size);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_PACKET_SIZE", column_width, loopkb_packet_size);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_MAX_SOCKETS", column_width, loopkb_max_sockets);
	retval += fprintf(fp, "============================\n");
	return retval;
}

int _loopkb_socket(int domain, int type, int protocol)
{
	__loopkb_log(log_level_trace, "_loopkb_socket %d %d %d", domain, type, protocol);

	int sockfd = _sys_socket(domain, type, protocol);
	if (sockfd >= 0)
	{
		_loopkb_nmq_socket(sockfd, domain, type, protocol);
	}
	return sockfd;
}

int _loopkb_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_connect");
	return _loopkb_nmq_connect(sockfd, addr, addrlen);
}

int _loopkb_accept(int sockfd, struct sockaddr *restrict addr, socklen_t* restrict addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_accept %d", sockfd);

	int client_sock = _sys_accept(sockfd, addr, addrlen);
	if (client_sock >= 0)
	{
		_loopkb_nmq_accept(client_sock, addr, addrlen);
	}
	else
	{
		fprintf(stderr, "accept: %s\n", strerror(errno));
	}
	return client_sock;
}

int _loopkb_close(int fd)
{
	int retval = _sys_close(fd);
	if (fd >= 0)
	{
		__loopkb_log(log_level_trace, "_loopkb_close %d", fd);
		_loopkb_nmq_close(fd);
	}
	else
	{
		fprintf(stderr, "close: %s\n", strerror(errno));
	}
	return retval;
}

int _loopkb_select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout)
{
	if (timeout != NULL)
	{
		struct timespec ts;
		// Convert timeout usec to timespec (ns)
		ts.tv_sec = timeout->tv_sec;
		ts.tv_nsec = timeout->tv_usec * 1000;
		return _loopkb_nmq_pselect(nfds, readfds, writefds, exceptfds, &ts, NULL);
	}
	else
	{
		return _loopkb_nmq_pselect(nfds, readfds, writefds, exceptfds, NULL, NULL);
	}
}

int _loopkb_pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask)
{
	return _loopkb_nmq_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

ssize_t _loopkb_send(int sockfd, const void* buf, size_t len, int flags)
{
	const ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, NULL, 0);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	return _sys_send(sockfd, buf, len, flags);
}

ssize_t _loopkb_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	const ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, dest_addr, addrlen);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	return _sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t _loopkb_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	return _sys_sendmsg(sockfd, msg, flags);
}

ssize_t _loopkb_recv(int sockfd, void* buf, size_t len, int flags)
{
	const ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, NULL, 0);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}

	return _sys_recv(sockfd, buf, len, flags);
}

ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t* restrict addrlen)
{
	const ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, src_addr, addrlen);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}
	return _sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t _loopkb_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return _sys_recvmsg(sockfd, msg, flags);
}

VISIBILITY_DEFAULT
int socket(int domain, int type, int protocol)
{
	return _loopkb_socket(domain, type, protocol);
}

VISIBILITY_DEFAULT
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return _loopkb_connect(sockfd, addr, addrlen);
}

VISIBILITY_DEFAULT
int accept(int sockfd, struct sockaddr *restrict addr, socklen_t* restrict addrlen)
{
	return _loopkb_accept(sockfd, addr, addrlen);
}

VISIBILITY_DEFAULT
int close(int fd)
{
	return _loopkb_close(fd);
}

VISIBILITY_DEFAULT
int select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout)
{
	return _loopkb_select(nfds, readfds, writefds, exceptfds, timeout);
}

VISIBILITY_DEFAULT
int pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask)
{
	return _loopkb_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

VISIBILITY_DEFAULT
ssize_t send(int sockfd, const void* buf, size_t len, int flags)
{
	return _loopkb_send(sockfd, buf, len, flags);
}

VISIBILITY_DEFAULT
ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return _loopkb_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

VISIBILITY_DEFAULT
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	return _loopkb_sendmsg(sockfd, msg, flags);
}

VISIBILITY_DEFAULT
ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
	return _loopkb_recv(sockfd, buf, len, flags);
}

VISIBILITY_DEFAULT
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t* restrict addrlen)
{
	return _loopkb_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

VISIBILITY_DEFAULT
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return _loopkb_recvmsg(sockfd, msg, flags);
}
