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

__attribute__((constructor))
static void _loopkb_init()
{
	loopkb_log_level_stdout = log_level_info;
	loopkb_log_level_stderr = log_level_info;

	if (getenv("LOOPKB_DEBUG") != NULL && strcmp(getenv("LOOPKB_DEBUG"), "1") == 0)
	{
		loopkb_log_level_stdout = log_level_debug;
		loopkb_log_level_stderr = log_level_debug;
	}
}

int _loopkb_socket(int domain, int type, int protocol)
{
	static socket_function_t _sys_socket = NULL;
	if (_sys_socket == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_socket = (socket_function_t) dlsym(RTLD_NEXT, "socket");
#pragma GCC diagnostic pop
	}

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
	static connect_function_t _sys_connect = NULL;
	if (_sys_connect == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_connect = (connect_function_t) dlsym(RTLD_NEXT, "connect");
#pragma GCC diagnostic pop
	}

	__loopkb_log(log_level_trace, "_loopkb_connect");

	// Make socket blocking, so we know what is the other endpoint of the connection
	// TODO perform this only if target is localhost in any way
	int flags = fcntl(sockfd, F_GETFL, 0);
	int orig_flags = flags;
	flags &= ~SOCK_NONBLOCK;
	if (fcntl(sockfd, F_SETFL, flags) != 0)
	{
		fprintf(stderr, "fcntl: %s\n", strerror(errno));
	}

	int retval = _sys_connect(sockfd, addr, addrlen);
	if (retval >= 0)
	{
		_loopkb_nmq_connect(sockfd, addr, addrlen);
	}
	else
	{
		// TODO handle non blocking sockets
		fprintf(stderr, "connect: %s\n", strerror(errno));
	}

	if (fcntl(sockfd, F_SETFL, orig_flags) != 0)
	{
		fprintf(stderr, "fcntl: %s\n", strerror(errno));
	}

	return retval;
}

int _loopkb_accept(int sockfd, struct sockaddr *restrict addr, socklen_t* restrict addrlen)
{
	static accept_function_t _sys_accept = NULL;
	if (_sys_accept == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_accept = (accept_function_t) dlsym(RTLD_NEXT, "accept");
#pragma GCC diagnostic pop
	}

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
	static close_function_t _sys_close = NULL;
	if (_sys_close == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_close = (close_function_t) dlsym(RTLD_NEXT, "close");
#pragma GCC diagnostic pop
	}

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
	return _loopkb_nmq_select(nfds, readfds, writefds, exceptfds, timeout);
}

ssize_t _loopkb_send(int sockfd, const void* buf, size_t len, int flags)
{
	static send_function_t _sys_send = NULL;
	if (_sys_send == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_send = (send_function_t) dlsym(RTLD_NEXT, "send");
#pragma GCC diagnostic pop
	}

	ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, NULL, 0);
	if (offload_send_retval != -1)
	{
		return offload_send_retval;
	}
	return _sys_send(sockfd, buf, len, flags);
}

ssize_t _loopkb_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	static sendto_function_t _sys_sendto = NULL;
	if (_sys_sendto == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_sendto = (sendto_function_t) dlsym(RTLD_NEXT, "sendto");
#pragma GCC diagnostic pop
	}

	_loopkb_nmq_send(sockfd, buf, len, flags, dest_addr, addrlen);
	return _sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t _loopkb_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	static sendmsg_function_t _sys_sendmsg = NULL;
	if (_sys_sendmsg == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_sendmsg = (sendmsg_function_t) dlsym(RTLD_NEXT, "sendmsg");
#pragma GCC diagnostic pop
	}

	return _sys_sendmsg(sockfd, msg, flags);
}

ssize_t _loopkb_recv(int sockfd, void* buf, size_t len, int flags)
{
	static recv_function_t _sys_recv = NULL;
	if (_sys_recv == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_recv = (recv_function_t) dlsym(RTLD_NEXT, "recv");
#pragma GCC diagnostic pop
	}

	ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, NULL, 0);
	if (offload_recv_retval != -1)
	{
		return offload_recv_retval;
	}

	return _sys_recv(sockfd, buf, len, flags);
}

ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t* restrict addrlen)
{
	static recvfrom_function_t _sys_recvfrom = NULL;
	if (_sys_recvfrom == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_recvfrom = (recvfrom_function_t) dlsym(RTLD_NEXT, "recvfrom");
#pragma GCC diagnostic pop
	}

	ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, src_addr, addrlen);
	if (offload_recv_retval > 0)
	{
		return offload_recv_retval;
	}
	return _sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t _loopkb_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	static recvmsg_function_t _sys_recvmsg = NULL;
	if (_sys_recvmsg == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_recvmsg = (recvmsg_function_t) dlsym(RTLD_NEXT, "recvmsg");
#pragma GCC diagnostic pop
	}

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
