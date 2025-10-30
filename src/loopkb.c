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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"
#include "loopkb.h"
#include "nmq-backend.h"

#define VISIBILITY_DEFAULT __attribute__((__visibility__("default")))

char loopkb_log_level[16];
char loopkb_socket_dir[128];
size_t loopkb_ring_size = 15;
size_t loopkb_ring_warmup_rounds = 0;
size_t loopkb_packet_size = LOOPKB_PACKET_SIZE_MAX;
size_t loopkb_offloaded_packet_size = LOOPKB_PACKET_SIZE_MAX;
size_t loopkb_max_sockets = 128;
size_t offloaded_addresses_count = 0;
struct address_mask_t offloaded_addresses[32];

socket_function_t _sys_socket = NULL;
connect_function_t _sys_bind = NULL;
connect_function_t _sys_connect = NULL;
accept_function_t _sys_accept = NULL;
accept4_function_t _sys_accept4 = NULL;
close_function_t _sys_close = NULL;
select_function_t _sys_select = NULL;
pselect_function_t _sys_pselect = NULL;
poll_function_t _sys_poll = NULL;
ppoll_function_t _sys_ppoll = NULL;
send_function_t _sys_send = NULL;
sendto_function_t _sys_sendto = NULL;
sendmsg_function_t _sys_sendmsg = NULL;
write_function_t _sys_write = NULL;
recv_function_t _sys_recv = NULL;
recvfrom_function_t _sys_recvfrom = NULL;
recvmsg_function_t _sys_recvmsg = NULL;
read_function_t _sys_read = NULL;
fcntl_function_t _sys_fcntl = NULL;
fcntl64_function_t _sys_fcntl64 = NULL;
sigaction_function_t _sys_sigaction = NULL;

#ifndef RTLD_NEXT
#define OVERRIDE_FUNCTION(function_type, function_name, function_variable) \
	if (__libc_handle == NULL) \
	{ \
		__libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL); \
	} \
	if (__libc_handle == NULL) \
	{ \
		__libc_handle = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL); \
	} \
	if (__libc_handle != NULL) \
	{ \
		(function_variable) = (function_type) dlsym(__libc_handle, #function_name); \
	} \

#else
// Need to disable -Wpedantic for that macro, otherwise you can use:
// *(void **) (&function_variable) = dlsym(RTLD_NEXT, #function_name);
#define OVERRIDE_FUNCTION(function_type, function_name, function_variable) \
	if (function_variable == NULL) \
	{ \
		function_variable = (function_type) dlsym(RTLD_NEXT, #function_name); \
	} \

#endif

int _loopkb_interruped = 0;

// Interrupting signals to override
static const int interrupting_signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM, SIGPIPE, SIGCHLD };
static struct sigaction _loopkb_saved_signal_handlers[NSIG];

static int _loopkb_is_interrupting_signal(int sig)
{
	for (size_t i = 0; i < sizeof(interrupting_signals) / sizeof(interrupting_signals[0]); i++)
	{
		if (interrupting_signals[i] == sig)
		{
			return 1;
		}
	}

	return 0;
}

// Our chaining wrapper that will be installed in place of the app's handler
static void _loopkb_signal_handler_wrapper(int signo)
{
	_loopkb_interruped = 1;
	__loopkb_log(log_level_trace, "_loopkb_signal_handler_wrapper: Interrupted");

	struct sigaction* orig = &_loopkb_saved_signal_handlers[signo];
	if (orig->sa_handler == SIG_IGN || orig->sa_handler == SIG_DFL || orig->sa_handler == _loopkb_signal_handler_wrapper)
	{
		return;
	}

	// Call the original handler
	orig->sa_handler(signo);
}

__attribute__((constructor))
static void _loopkb_init()
{
	loopkb_log_level_stdout = log_level_error;
	loopkb_log_level_stderr = log_level_error;

	strcpy(loopkb_log_level, "warn");

	const char* loopkb_log_level_ = getenv("LOOPKB_LOG_LEVEL");
	if (NULL != loopkb_log_level_)
	{
		if (strncasecmp(loopkb_log_level_, "error", 5) == 0)
		{
			loopkb_log_level_stdout = log_level_error;
			loopkb_log_level_stderr = log_level_error;
			strcpy(loopkb_log_level, loopkb_log_level_);
		}
		else if (strncasecmp(loopkb_log_level_, "warn", 4) == 0)
		{
			loopkb_log_level_stdout = log_level_warning;
			loopkb_log_level_stderr = log_level_warning;
			strcpy(loopkb_log_level, loopkb_log_level_);
		}
		else if (strncasecmp(loopkb_log_level_, "info", 4) == 0)
		{
			loopkb_log_level_stdout = log_level_info;
			loopkb_log_level_stderr = log_level_info;
			strcpy(loopkb_log_level, loopkb_log_level_);
		}
		else if (strncasecmp(loopkb_log_level_, "debug", 5) == 0)
		{
			loopkb_log_level_stdout = log_level_debug;
			loopkb_log_level_stderr = log_level_debug;
			strcpy(loopkb_log_level, loopkb_log_level_);
		}
		else if (strncasecmp(loopkb_log_level_, "trace", 5) == 0)
		{
			loopkb_log_level_stdout = log_level_trace;
			loopkb_log_level_stderr = log_level_trace;
			strcpy(loopkb_log_level, loopkb_log_level_);
		}
		else
		{
			__loopkb_log(log_level_error, "Unsupported LOOPKB_LOG_LEVEL=%s", loopkb_log_level_);
		}
	}

	strcpy(loopkb_socket_dir, "");
	const char* loopkb_socket_dir_ = getenv("LOOPKB_SOCKET_DIR");
	if (NULL != loopkb_socket_dir_)
	{
		struct stat statbuf;
		if (stat(loopkb_socket_dir_, &statbuf) != 0)
		{
			__loopkb_log(log_level_error, "Cannot set LOOPKB_SOCKET_DIR='%s', directory does not exist. Using local directory instead", loopkb_socket_dir_);
		}
		else if (!S_ISDIR(statbuf.st_mode))
		{
			__loopkb_log(log_level_error, "Cannot set LOOPKB_SOCKET_DIR='%s', path is not a directory. Using local directory instead", loopkb_socket_dir_);
		}
		else
		{
			strncpy(loopkb_socket_dir, loopkb_socket_dir_, sizeof(loopkb_socket_dir) - 1);
			if (loopkb_socket_dir[strlen(loopkb_socket_dir) - 1] == '/')
			{
				loopkb_socket_dir[strlen(loopkb_socket_dir) - 1] = '\0';
			}
			__loopkb_log(log_level_info, "Setting LOOPKB_SOCKET_DIR='%s'", loopkb_socket_dir);
		}
	}

	if (getenv("LOOPKB_RING_SIZE") != NULL)
	{
		loopkb_ring_size = atoi(getenv("LOOPKB_RING_SIZE"));
	}

	if (getenv("LOOPKB_RING_WARMUP_ROUNDS") != NULL)
	{
		loopkb_ring_warmup_rounds = atoi(getenv("LOOPKB_RING_WARMUP_ROUNDS"));
	}

	if (getenv("LOOPKB_PACKET_SIZE") != NULL)
	{
		loopkb_packet_size = atoi(getenv("LOOPKB_PACKET_SIZE"));
		if (loopkb_packet_size > LOOPKB_PACKET_SIZE_MAX)
		{
			loopkb_packet_size = LOOPKB_PACKET_SIZE_MAX;
			__loopkb_log(log_level_warning, "Cannot set LOOPKB_PACKET_SIZE=%d, maximum is %zu", loopkb_packet_size, LOOPKB_PACKET_SIZE_MAX);
		}
	}
	loopkb_offloaded_packet_size = loopkb_packet_size + loopkb_offloaded_packet_payload_size;

	if (getenv("LOOPKB_MAX_SOCKETS") != NULL)
	{
		loopkb_max_sockets = atoi(getenv("LOOPKB_MAX_SOCKETS"));
	}

	if (getenv("LOOPKB_OFFLOAD_ADDR") != NULL)
	{
		_loopkb_parse_offloaded_addresses(getenv("LOOPKB_OFFLOAD_ADDR"));
	}
	else
	{
		// 127.0.0.1/8 and ::1/128 by default
		_loopkb_parse_offloaded_addresses("127.0.0.1/255.255.255.0,::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	}

	if (loopkb_log_level_stdout <= log_level_debug)
	{
		_loopkb_banner(stdout);
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	static void* __libc_handle = NULL;
	(void) __libc_handle;
	OVERRIDE_FUNCTION(socket_function_t, socket, _sys_socket);
	OVERRIDE_FUNCTION(bind_function_t, bind, _sys_bind);
	OVERRIDE_FUNCTION(connect_function_t, connect, _sys_connect);
	OVERRIDE_FUNCTION(accept_function_t, accept, _sys_accept);
	OVERRIDE_FUNCTION(close_function_t, close, _sys_close);
	OVERRIDE_FUNCTION(select_function_t, select, _sys_select);
	OVERRIDE_FUNCTION(poll_function_t, poll, _sys_poll);
	OVERRIDE_FUNCTION(send_function_t, send, _sys_send);
	OVERRIDE_FUNCTION(sendto_function_t, sendto, _sys_sendto);
	OVERRIDE_FUNCTION(sendmsg_function_t, sendmsg, _sys_sendmsg);
	OVERRIDE_FUNCTION(write_function_t, write, _sys_write);
	OVERRIDE_FUNCTION(recv_function_t, recv, _sys_recv);
	OVERRIDE_FUNCTION(recvfrom_function_t, recvfrom, _sys_recvfrom);
	OVERRIDE_FUNCTION(recvmsg_function_t, recvmsg, _sys_recvmsg);
	OVERRIDE_FUNCTION(read_function_t, read, _sys_read);
	OVERRIDE_FUNCTION(fcntl_function_t, fcntl, _sys_fcntl);
	OVERRIDE_FUNCTION(fcntl64_function_t, fcntl64, _sys_fcntl64);
	OVERRIDE_FUNCTION(sigaction_function_t, sigaction, _sys_sigaction);

#ifdef _GNU_SOURCE
	OVERRIDE_FUNCTION(accept4_function_t, accept4, _sys_accept4);
	OVERRIDE_FUNCTION(pselect_function_t, pselect, _sys_pselect);
	OVERRIDE_FUNCTION(ppoll_function_t, ppoll, _sys_ppoll);
#endif

#pragma GCC diagnostic pop
}

const char* _loopkb_offloaded_addresses_to_str(struct address_mask_t* offloaded_addresses, size_t offloaded_addresses_count, char* buffer, size_t size)
{
	if (size > 0)
	{
		buffer[0] = '\0';
	}

	char ip_addr_str[INET6_ADDRSTRLEN];
	char mask_str[INET6_ADDRSTRLEN];

	int offset = 0;
	for (size_t i = 0; i < offloaded_addresses_count; ++i)
	{
		struct address_mask_t* address_mask = &offloaded_addresses[i];

		_loopkb_nmq_inet_ntop((const struct sockaddr*) &address_mask->addr, ip_addr_str);
		_loopkb_nmq_inet_ntop((const struct sockaddr*) &address_mask->mask, mask_str);

		offset += snprintf(buffer + offset, size - offset, "%s/%s,", ip_addr_str, mask_str);

		/*struct sockaddr_in addr4;
		addr4.sin_family = AF_INET;

		addr4.sin_addr.s_addr = offloaded_addresses[i].ip_addr;
		_loopkb_nmq_inet_ntop((const struct sockaddr*) &addr4, ip_addr_str);

		addr4.sin_addr.s_addr = offloaded_addresses[i].mask;
		_loopkb_nmq_inet_ntop((const struct sockaddr*) &addr4, mask_str);*/
	}

	if (offset - 1 < (int) size && offset > 0)
	{
		buffer[offset - 1] = '\0';
	}

	return buffer;
}

int _loopkb_banner(FILE* fp)
{
	int column_width = 30;

	size_t offload_socket_buffer_size = 2048;
	char offload_socket_buffer[2048];

	int retval = 0;
	retval += fprintf(fp, "============================\n");
	retval += fprintf(fp, "========== LoopKB ==========\n");
	retval += fprintf(fp, "============================\n");
	retval += fprintf(fp, "%-*s = %-*s\n", column_width, "LOOPKB_LOG_LEVEL", column_width, loopkb_log_level);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_RING_SIZE", column_width, loopkb_ring_size);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_RING_WARMUP_ROUNDS", column_width, loopkb_ring_warmup_rounds);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_PACKET_SIZE", column_width, loopkb_packet_size);
	retval += fprintf(fp, "%-*s = %-*zu\n", column_width, "LOOPKB_MAX_SOCKETS", column_width, loopkb_max_sockets);
	retval += fprintf(fp, "%-*s = %-*s\n", column_width, "LOOPKB_SOCKET_DIR", column_width, loopkb_socket_dir);
	retval += fprintf(fp, "%-*s = %-*s\n", column_width, "LOOPKB_OFFLOAD_ADDR", column_width, _loopkb_offloaded_addresses_to_str(offloaded_addresses, offloaded_addresses_count, offload_socket_buffer, offload_socket_buffer_size));
	retval += fprintf(fp, "============================\n");
	return retval;
}

int _loopkb_parse_offloaded_addresses(const char* offloaded_addresses_string)
{
	size_t count = 0;
	__uint128_t ip_addr6;
	__uint128_t mask6;
	uint32_t ip_addr4;
	uint32_t mask4;

	char* s = strdup(offloaded_addresses_string);

	char* token = strtok(s, ",");
	while (token)
	{
		char* slash = strchr(token, '/');
		if (slash)
		{
			*slash = '\0';
			const char* ip_addr = token;
			const char* mask = slash + 1;

			if (1 == inet_pton(AF_INET6, ip_addr, &ip_addr6) && 1 == inet_pton(AF_INET6, mask, &mask6))
			{
				__loopkb_log(log_level_trace, "_loopkb_parse_offloaded_addresses: Offloading address (ipv6): %s/%s", ip_addr, mask);
				struct address_mask_t* address_mask = &offloaded_addresses[offloaded_addresses_count];

				address_mask->addr6.sin6_family = AF_INET6;
				address_mask->mask6.sin6_family = AF_INET6;
				memcpy(&address_mask->addr6.sin6_addr.s6_addr, &ip_addr6, sizeof(address_mask->addr6.sin6_addr));
				memcpy(&address_mask->mask6.sin6_addr.s6_addr, &mask6, sizeof(address_mask->mask6.sin6_addr));

				++offloaded_addresses_count;
				++count;
			}
			else if (1 == inet_pton(AF_INET, ip_addr, &ip_addr4) && 1 == inet_pton(AF_INET, mask, &mask4))
			{
				__loopkb_log(log_level_trace, "_loopkb_parse_offloaded_addresses: Offloading address (ipv4): %s/%s", ip_addr, mask);
				struct address_mask_t* address_mask = &offloaded_addresses[offloaded_addresses_count];

				address_mask->addr4.sin_family = AF_INET;
				address_mask->mask4.sin_family = AF_INET;
				address_mask->addr4.sin_addr.s_addr = ip_addr4;
				address_mask->mask4.sin_addr.s_addr = mask4;

				++offloaded_addresses_count;
				++count;
			}
			else
			{
				__loopkb_log(log_level_error, "_loopkb_parse_offloaded_addresses: Error offloading address: %s/%s", ip_addr, mask);
			}
		}
		token = strtok(NULL, ",");
	}
	free(s);

	return count;
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

int _loopkb_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_bind %d", sockfd);

	int retval = _sys_bind(sockfd, addr, addrlen);
	if (retval >= 0)
	{
		_loopkb_nmq_bind(sockfd, addr, addrlen);
	}
	return retval;
}

int _loopkb_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_connect");
	return _loopkb_nmq_connect(sockfd, addr, addrlen);
}

int _loopkb_accept(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrlen, int flags)
{
	__loopkb_log(log_level_trace, "_loopkb_accept %d", sockfd);

#ifdef _GNU_SOURCE
	int client_sock = _sys_accept4(sockfd, addr, addrlen, flags);
#else
	int client_sock = _sys_accept(sockfd, addr, addrlen);
	flags = 0;
#endif
	if (client_sock >= 0)
	{
		_loopkb_nmq_accept(client_sock, addr, addrlen, flags);
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

int _loopkb_select(int nfds, fd_set* restrict readfds, fd_set* restrict writefds, fd_set* restrict exceptfds, struct timeval* restrict timeout)
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

int _loopkb_pselect(int nfds, fd_set* restrict readfds, fd_set* restrict writefds, fd_set* restrict exceptfds, const struct timespec* restrict timeout, const sigset_t* restrict sigmask)
{
	return _loopkb_nmq_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int _loopkb_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
	struct timespec ts;
	// Convert timeout milliseconds to timespec (ns)
	ts.tv_sec = timeout / 1000; // seconds
	ts.tv_nsec = (timeout % 1000) * 1000000; // nanoseconds
	return _loopkb_nmq_ppoll(fds, nfds, &ts, NULL);
}

int _loopkb_ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask)
{
	return _loopkb_nmq_ppoll(fds, nfds, tmo_p, sigmask);
}

ssize_t _loopkb_send(int sockfd, const void* buf, size_t len, int flags)
{
	const ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, NULL, 0);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	else if (offload_send_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_send(sockfd, buf, len, flags);
}

ssize_t _loopkb_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	const ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, dest_addr, addrlen);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	else if (offload_send_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t _loopkb_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
	if (msg == NULL || msg->msg_iovlen <= 0)
	{
		errno = EINVAL;
		return -1;
	}

	if (msg->msg_iovlen != 1)
	{
		errno = ENOTSUP;
		return -1;
	}

	const void* buf = msg->msg_iov[0].iov_base;
	const size_t len = msg->msg_iov[0].iov_len;
	const struct sockaddr* dest = (const struct sockaddr*) msg->msg_name;
	socklen_t addrlen = msg->msg_namelen;

	const ssize_t offload_send_retval = _loopkb_nmq_send(sockfd, buf, len, flags, dest, addrlen);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	else if (offload_send_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_sendmsg(sockfd, msg, flags);
}

ssize_t _loopkb_write(int fd, const void* buf, size_t count)
{
	const int flags = 0;
	const ssize_t offload_send_retval = _loopkb_nmq_send(fd, buf, count, flags, NULL, 0);
	if (offload_send_retval >= 0)
	{
		return offload_send_retval;
	}
	return _sys_write(fd, buf, count);
}

ssize_t _loopkb_recv(int sockfd, void* buf, size_t len, int flags)
{
	const ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, NULL, 0);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}
	else if (offload_recv_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_recv(sockfd, buf, len, flags);
}

ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* restrict src_addr, socklen_t* restrict addrlen)
{
	const ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, src_addr, addrlen);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}
	else if (offload_recv_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t _loopkb_recvmsg(int sockfd, struct msghdr* msg, int flags)
{
	if (msg == NULL || msg->msg_iovlen <= 0)
	{
		errno = EINVAL;
		return -1;
	}

	if (msg->msg_iovlen != 1)
	{
		errno = ENOTSUP;
		return -1;
	}

	void* buf = msg->msg_iov[0].iov_base;
	const size_t len = msg->msg_iov[0].iov_len;
	socklen_t* addrlen = msg->msg_namelen > 0 ? &msg->msg_namelen : NULL;

	const ssize_t offload_recv_retval = _loopkb_nmq_receive(sockfd, buf, len, flags, (struct sockaddr*) msg->msg_name, addrlen);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}
	else if (offload_recv_retval == LOOPKB_OFFLOADED_SOCKET_HAD_ERRORS)
	{
		return -1;
	}

	return _sys_recvmsg(sockfd, msg, flags);
}

ssize_t _loopkb_read(int fd, void* buf, size_t count)
{
	const int flags = 0;
	const ssize_t offload_recv_retval = _loopkb_nmq_receive(fd, buf, count, flags, NULL, 0);
	if (offload_recv_retval >= 0)
	{
		return offload_recv_retval;
	}
	return _sys_read(fd, buf, count);
}

int _loopkb_fcntl(int fd, int op, int arg)
{
	const ssize_t offload_fcntl_retval = _loopkb_nmq_fcntl64(fd, op, arg);
	if (offload_fcntl_retval >= 0)
	{
		return offload_fcntl_retval;
	}
	return _sys_fcntl(fd, op, arg);
}

int _loopkb_fcntl64(int fd, int op, int arg)
{
	const ssize_t offload_fcntl_retval = _loopkb_nmq_fcntl64(fd, op, arg);
	if (offload_fcntl_retval >= 0)
	{
		return offload_fcntl_retval;
	}
	return _sys_fcntl64(fd, op, arg);
}

int _loopkb_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
	if (oldact != NULL)
	{
		memset(oldact, 0, sizeof(*oldact));
	}

	// Handler not installed - just a query
	if (act == NULL)
	{
		return _sys_sigaction(signum, NULL, oldact);
	}

	// Not ignored - but is interrupting
	if (_loopkb_is_interrupting_signal(signum) && act->sa_handler != SIG_IGN)
	{
		memcpy(&_loopkb_saved_signal_handlers[signum], act, sizeof(struct sigaction));

		struct sigaction wrap = *act;
		wrap.sa_handler = _loopkb_signal_handler_wrapper;
		wrap.sa_flags &= ~SA_RESTART;

		int ret = _sys_sigaction(signum, &wrap, oldact);
		if (ret == 0)
		{
			__loopkb_log(log_level_trace, "_loopkb_sigaction: Chained signal handler for %d (%s)\n", signum, strsignal(signum));
		}
		return ret;
	}

	// Pass through unchanged
	return _sys_sigaction(signum, act, oldact);
}

VISIBILITY_DEFAULT
int socket(int domain, int type, int protocol)
{
	return _loopkb_socket(domain, type, protocol);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
VISIBILITY_DEFAULT
int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	return _loopkb_bind(sockfd, addr, addrlen);
}

VISIBILITY_DEFAULT
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	return _loopkb_connect(sockfd, addr, addrlen);
}

VISIBILITY_DEFAULT
int accept(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrlen)
{
	const int flags = 0;
	return _loopkb_accept(sockfd, addr, addrlen, flags);
}

VISIBILITY_DEFAULT
int accept4(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrlen, int flags)
{
	return _loopkb_accept(sockfd, addr, addrlen, flags);
}
#pragma GCC diagnostic pop

VISIBILITY_DEFAULT
int close(int fd)
{
	return _loopkb_close(fd);
}

VISIBILITY_DEFAULT
int select(int nfds, fd_set* restrict readfds, fd_set* restrict writefds, fd_set* restrict exceptfds, struct timeval* restrict timeout)
{
	return _loopkb_select(nfds, readfds, writefds, exceptfds, timeout);
}

VISIBILITY_DEFAULT
int pselect(int nfds, fd_set* restrict readfds, fd_set* restrict writefds, fd_set* restrict exceptfds, const struct timespec* restrict timeout, const sigset_t* restrict sigmask)
{
	return _loopkb_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

VISIBILITY_DEFAULT
int poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
	return _loopkb_poll(fds, nfds, timeout);
}

VISIBILITY_DEFAULT
int ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask)
{
	return _loopkb_ppoll(fds, nfds, tmo_p, sigmask);
}

VISIBILITY_DEFAULT
ssize_t send(int sockfd, const void* buf, size_t len, int flags)
{
	return _loopkb_send(sockfd, buf, len, flags);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
VISIBILITY_DEFAULT
ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	return _loopkb_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
#pragma GCC diagnostic pop

VISIBILITY_DEFAULT
ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
	return _loopkb_sendmsg(sockfd, msg, flags);
}

VISIBILITY_DEFAULT
ssize_t write(int fd, const void* buf, size_t count)
{
	return _loopkb_write(fd, buf, count);
}

VISIBILITY_DEFAULT
ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
	return _loopkb_recv(sockfd, buf, len, flags);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
VISIBILITY_DEFAULT
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* restrict src_addr, socklen_t* restrict addrlen)
{
	return _loopkb_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}
#pragma GCC diagnostic pop

VISIBILITY_DEFAULT
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)
{
	return _loopkb_recvmsg(sockfd, msg, flags);
}

VISIBILITY_DEFAULT
ssize_t read(int fd, void* buf, size_t count)
{
	return _loopkb_read(fd, buf, count);
}

VISIBILITY_DEFAULT
int fcntl(int fd, int op, ...)
{
	va_list va;
	va_start(va, op);
	unsigned long int arg = va_arg(va, unsigned long int);
	va_end(va);

	return _loopkb_fcntl(fd, op, arg);
}

VISIBILITY_DEFAULT
int fcntl64(int fd, int op, ...)
{
	va_list va;
	va_start(va, op);
	unsigned long int arg = va_arg(va, unsigned long int);
	va_end(va);

	return _loopkb_fcntl(fd, op, arg);
}

VISIBILITY_DEFAULT
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
	return _loopkb_sigaction(signum, act, oldact);
}
