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

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "nmq-backend.h"
#include "nmq.h"
#include "util.h"

#define MAX_SOCKET_FILE_MAPPING 1024
#define PACKET_SIZE 1500
#define RING_SIZE 15
#define LOOPKB_FILE_PREFIX "_loopkb_"

// Max filename length will be _loopkb_{FAMILY}.{PROTO}:{INET6_ADDRSTRLEN}:{PORT}:{INET6_ADDRSTRLEN}:{PORT}
// Family and proto are normally one char each, but allow for 2
// Port is 5 chars long
// _loopkb_ is 8 chars long
// All the other chars are 5 chars long (. and :)
// All in all, 256 chars should be more than enough
//#define PORT_LENGTH 5
//#define MAX_FILENAME_SIZE 8 + (INET6_ADDRSTRLEN * 2) + (PORT_LENGTH * 2) + 2 + 5
#define MAX_FILENAME_SIZE 256

typedef int (*select_function_t)(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout);

static const char eof[1] = { '\0' };

enum channel_type_t : uint8_t
{
	server_to_client_data = 0,
	client_to_server_data = 1,
	server_to_client_control = 2,
	client_to_server_control = 3,
	total_channels = 4,
};

struct socket_info_t
{
	int sock;
	union
	{
		struct
		{
			uint32_t ip_addr_1;
			uint32_t ip_addr_2;
		} ipv4;

		struct
		{
			__uint128_t ip_addr_1;
			__uint128_t ip_addr_2;
		} ipv6;
	};
	char ip_addr_1_str[INET6_ADDRSTRLEN];
	char ip_addr_2_str[INET6_ADDRSTRLEN];
	uint16_t port_1;
	uint16_t port_2;
	int family;
	int protocol;
};

struct offloaded_socket_t
{
	int sock;
	char* filename;
	struct context_t* context;
	struct node_t* node_data;
	struct node_t* node_control;
};

struct offloaded_socket_t socket_file_map[MAX_SOCKET_FILE_MAPPING];

struct ipv4_address_mask_t
{
	uint32_t ip_addr;
	uint32_t mask;
};

struct ipv6_address_mask_t
{
	__uint128_t ip_addr;
	__uint128_t mask;
};

size_t ipv4_loopback_addresses_count = 0;
struct ipv4_address_mask_t ipv4_loopback_addresses[32];

size_t ipv6_loopback_addresses_count = 0;
struct ipv6_address_mask_t ipv6_loopback_addresses[32];

__attribute__((constructor))
static void _loopkb_nmq_init()
{
	for (int i = 0; i < MAX_SOCKET_FILE_MAPPING; ++i)
	{
		socket_file_map[i].sock = -1;
		socket_file_map[i].filename = NULL;
		socket_file_map[i].context = NULL;
		socket_file_map[i].node_data = NULL;
		socket_file_map[i].node_control = NULL;
	}

	// 127.0.0.1/8
	inet_pton(AF_INET, "127.0.0.1", &ipv4_loopback_addresses[0].ip_addr);
	inet_pton(AF_INET, "255.0.0.0", &ipv4_loopback_addresses[0].mask);
	++ipv4_loopback_addresses_count;

	// ::1/128
	inet_pton(AF_INET6, "::1", &ipv6_loopback_addresses[0].ip_addr);
	inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &ipv6_loopback_addresses[0].ip_addr);
	++ipv6_loopback_addresses_count;
}

int _loopkb_nmq_get_socket_info(int sockfd, struct socket_info_t* socket_info, int direction)
{
	struct sockaddr_in6 addr;
	struct sockaddr_in* addr4 = (struct sockaddr_in*) &addr;
	struct sockaddr_in6* addr6 = (struct sockaddr_in6*) &addr;

	// Socket protocol
	int type = -1;
	socklen_t len = sizeof(int);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (char*) &type, &len);
	socket_info->protocol = type;

	len = sizeof(addr);

	if (getsockname(sockfd, (struct sockaddr*) &addr, &len) != 0)
	{
		__loopkb_log(log_level_error, "getsockname: %s", strerror(errno));
		return -1;
	}

	if (addr4->sin_family == AF_INET)
	{
		socket_info->family = addr4->sin_family;
		socket_info->ipv4.ip_addr_1 = *((int32_t*)(&addr4->sin_addr));
		socket_info->port_1 = ntohs(addr4->sin_port);

		if (NULL == inet_ntop(AF_INET, &addr4->sin_addr, socket_info->ip_addr_1_str, INET_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_get_socket_info: Error calling inet_ntop %s", strerror(errno));
			return -1;
		}
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		socket_info->family = addr6->sin6_family;
		socket_info->ipv6.ip_addr_1 = *((__uint128_t*)(&addr6->sin6_addr));
		socket_info->port_1 = ntohs(addr6->sin6_port);

		if (NULL == inet_ntop(AF_INET6, &addr6->sin6_addr, socket_info->ip_addr_1_str, INET6_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_get_socket_info: Error calling inet_ntop %s", strerror(errno));
			return -1;
		}
	}
	else
	{
		__loopkb_log(log_level_error, "_loopkb_get_socket_info: Unknown address family %d for socket %d", addr4->sin_family, sockfd);
		return -1;
	}

	if (getpeername(sockfd, (struct sockaddr*) &addr, &len) != 0)
	{
		__loopkb_log(log_level_error, "_loopkb_get_socket_info: Error calling getpeername %s", strerror(errno));
		return -1;
	}

	if (addr4->sin_family == AF_INET)
	{
		socket_info->ipv4.ip_addr_2 = *((int32_t*)(&addr4->sin_addr));
		socket_info->port_2 = ntohs(addr4->sin_port);

		if (NULL == inet_ntop(AF_INET, &addr4->sin_addr, socket_info->ip_addr_2_str, INET_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_get_socket_info: Error calling inet_ntop %s", strerror(errno));
			return -1;
		}
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		socket_info->ipv6.ip_addr_2 = *((__uint128_t*)(&addr6->sin6_addr));
		socket_info->port_2 = ntohs(addr6->sin6_port);

		if (NULL == inet_ntop(AF_INET6, &addr6->sin6_addr, socket_info->ip_addr_2_str, INET6_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_get_socket_info: Error calling inet_ntop %s", strerror(errno));
			return -1;
		}
	}
	else
	{
		__loopkb_log(log_level_error, "_loopkb_get_socket_info: Unknown address family %d for socket %d", addr4->sin_family, sockfd);
		return -1;
	}

	if (direction == 1)
	{
		uint32_t ip = socket_info->ipv4.ip_addr_1;
		uint16_t port = socket_info->port_1;
		char ip_str[INET6_ADDRSTRLEN];
		strncpy(ip_str, socket_info->ip_addr_1_str, INET6_ADDRSTRLEN);

		socket_info->ipv4.ip_addr_1 = socket_info->ipv4.ip_addr_2;
		socket_info->port_1 = socket_info->port_2;
		strncpy(socket_info->ip_addr_1_str, socket_info->ip_addr_2_str, INET6_ADDRSTRLEN);

		socket_info->ipv4.ip_addr_2 = ip;
		socket_info->port_2 = port;
		strncpy(socket_info->ip_addr_2_str, ip_str, INET6_ADDRSTRLEN);
	}

	return 0;
}

const char* _loopkb_nmq_generate_filename_for_socket(int sockfd, int direction, char* buffer, size_t len)
{
	struct socket_info_t socket_info;
	_loopkb_nmq_get_socket_info(sockfd, &socket_info, direction);

	if (socket_info.family == AF_INET)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv4.%d.%s:%d:%s:%d", socket_info.protocol, socket_info.ip_addr_1_str, socket_info.port_1, socket_info.ip_addr_2_str, socket_info.port_2);
	}
	else if (socket_info.family == AF_INET6)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv6.%d.%s:%d:%s:%d", socket_info.protocol, socket_info.ip_addr_1_str, socket_info.port_1, socket_info.ip_addr_2_str, socket_info.port_2);
	}
	else
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "%d.%d.%u:%d:%u:%d", socket_info.family, socket_info.protocol, socket_info.ipv4.ip_addr_1, socket_info.port_1, socket_info.ipv4.ip_addr_2, socket_info.port_2);
	}

	__loopkb_log(log_level_debug, "_loopkb_nmq_generate_filename_for_socket: Socket %d will use filename %s", sockfd, buffer);
	return buffer;
}

bool _loopkb_nmq_is_offloaded_socket(int sockfd)
{
	return socket_file_map[sockfd].sock != -1;
}

void _loopkb_nmq_add_offloaded_socket(int sockfd, struct socket_info_t* socket_info, int direction)
{
	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Adding offloaded socket: %d", sockfd);
	assert(direction == 0 || direction == 1);
	socket_file_map[sockfd].sock = sockfd;
	socket_file_map[sockfd].filename = malloc(MAX_FILENAME_SIZE);
	_loopkb_nmq_generate_filename_for_socket(sockfd, direction, socket_file_map[sockfd].filename, MAX_FILENAME_SIZE);
	assert(socket_file_map[sockfd].context == NULL);
	assert(socket_file_map[sockfd].node_data == NULL);
	assert(socket_file_map[sockfd].node_control == NULL);
	socket_file_map[sockfd].context = malloc(sizeof(struct context_t));
	socket_file_map[sockfd].node_data = malloc(sizeof(struct node_t));
	socket_file_map[sockfd].node_control = malloc(sizeof(struct node_t));
	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Socket offloaded: %d (%s) direction: %d", sockfd, socket_file_map[sockfd].filename, direction);

	if (direction == 0)
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_create");
		if (context_create(socket_file_map[sockfd].context, socket_file_map[sockfd].filename, total_channels, RING_SIZE, PACKET_SIZE) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Error creating context %s", strerror(errno));
			socket_file_map[sockfd].sock = sockfd;
			return;
		}
	}
	else
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_open");
		int fd = open(socket_file_map[sockfd].filename, O_RDWR);
		while (fd == -1)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Waiting for file to become ready at %s...", socket_file_map[sockfd].filename);
			usleep(1000); // 1ms
			fd = open(socket_file_map[sockfd].filename, O_RDWR);
		}
		close(fd);

		if (context_open(socket_file_map[sockfd].context, socket_file_map[sockfd].filename, 2, RING_SIZE, PACKET_SIZE) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Cannot open context %s: %s", socket_file_map[sockfd].filename, strerror(errno));
			socket_file_map[sockfd].sock = sockfd;
			return;
		}
	}

	const unsigned int ring_from = direction;
	const unsigned int ring_to = direction == server_to_client_data ? client_to_server_data : server_to_client_data;
	const unsigned int ring_from_control = ring_from + 2;
	const unsigned int ring_to_control = ring_to + 2;
	__loopkb_log(log_level_info, "_loopkb_nmq_add_offloaded_socket: Socket %d uses recv %d, send %d, recv_control: %d, send_control: %d",
				 sockfd, ring_from, ring_to, ring_from_control, ring_to_control);
	node_init(socket_file_map[sockfd].node_data, socket_file_map[sockfd].context, ring_from);
	node_init(socket_file_map[sockfd].node_control, socket_file_map[sockfd].context, ring_from_control);
}

void _loopkb_nmq_remove_offloaded_socket(int sockfd)
{
	if (socket_file_map[sockfd].sock != -1)
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Removing socket %d (%s)", sockfd, socket_file_map[sockfd].filename);

		unsigned int ring_to_control = socket_file_map[sockfd].node_control->node_ == server_to_client_control ? client_to_server_control : server_to_client_control;
		node_send(socket_file_map[sockfd].node_control, ring_to_control, eof, sizeof(eof));

		if (socket_file_map[sockfd].node_data->node_ == server_to_client_data)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Removing file %s", socket_file_map[sockfd].filename);
			unlink(socket_file_map[sockfd].filename);
		}

		socket_file_map[sockfd].sock = -1;
		free(socket_file_map[sockfd].filename);
		context_destroy(socket_file_map[sockfd].context);
		free(socket_file_map[sockfd].context);
		socket_file_map[sockfd].context = NULL;
		free(socket_file_map[sockfd].node_data);
		free(socket_file_map[sockfd].node_control);
		socket_file_map[sockfd].node_data = NULL;
		socket_file_map[sockfd].node_control = NULL;
	}
	else
	{
		__loopkb_log(log_level_trace, "_loopkb_nmq_remove_offloaded_socket: Socket %d was never offloaded", sockfd);
	}
}

bool _loopkb_nmq_should_offload_ipv4(uint32_t ip_addr_1, uint32_t ip_addr_2)
{
	for (size_t i = 0; i < ipv4_loopback_addresses_count; ++i)
	{
		const struct ipv4_address_mask_t* ipv4_address_mask = &ipv4_loopback_addresses[i];
		if ((ip_addr_1 & ipv4_address_mask->mask) == (ipv4_address_mask->ip_addr & ipv4_address_mask->mask) &&
				(ip_addr_2 & ipv4_address_mask->mask) == (ipv4_address_mask->ip_addr & ipv4_address_mask->mask))
		{
			return true;
		}
	}

	return false;
}

bool _loopkb_nmq_should_offload_ipv6(__uint128_t ip_addr_1, __uint128_t ip_addr_2)
{
	for (size_t i = 0; i < ipv6_loopback_addresses_count; ++i)
	{
		const struct ipv6_address_mask_t* ipv6_address_mask = &ipv6_loopback_addresses[i];
		if ((ip_addr_1 & ipv6_address_mask->mask) == (ipv6_address_mask->ip_addr & ipv6_address_mask->mask) &&
				(ip_addr_2 & ipv6_address_mask->mask) == (ipv6_address_mask->ip_addr & ipv6_address_mask->mask))
		{
			return true;
		}
	}

	return false;
}

bool _loopkb_nmq_should_offload_socket(int sockfd, const struct socket_info_t* socket_info)
{
	if (socket_info->protocol == SOCK_DGRAM || socket_info->protocol == SOCK_STREAM) // Only UDP and TCP
	{
		if (socket_info->port_1 != 0 && socket_info-> port_2 != 0) // Avoid listening sockets
		{
			if (socket_info->family == AF_INET)
			{
				return _loopkb_nmq_should_offload_ipv4(socket_info->ipv4.ip_addr_1, socket_info->ipv4.ip_addr_2);
			}
			else if (socket_info->family == AF_INET6)
			{
				return _loopkb_nmq_should_offload_ipv6(socket_info->ipv6.ip_addr_1, socket_info->ipv6.ip_addr_2);
			}
		}
	}

	return false;
}

bool _loopkb_nmq_can_send(int sockfd)
{
	const unsigned int ring_to = socket_file_map[sockfd].node_data->node_ == server_to_client_data ? client_to_server_data : server_to_client_data;
	return node_can_send(socket_file_map[sockfd].node_data, ring_to);
}

bool _loopkb_nmq_can_receive(int sockfd)
{
	const unsigned int ring_from = socket_file_map[sockfd].node_data->node_ == server_to_client_data ? client_to_server_data : server_to_client_data;
	return node_can_recv(socket_file_map[sockfd].node_data, ring_from);
}

int _loopkb_nmq_check_socket(int sockfd, int direction)
{
	struct socket_info_t socket_info;
	if (_loopkb_nmq_get_socket_info(sockfd, &socket_info, direction) >= 0)
	{
		if (_loopkb_nmq_should_offload_socket(sockfd, &socket_info) != 0)
		{
			__loopkb_log(log_level_info, "_loopkb_nmq_check_socket: Socket %d will be offloaded", sockfd);
			_loopkb_nmq_add_offloaded_socket(sockfd, &socket_info, direction);
		}
		else
		{
			__loopkb_log(log_level_trace, "_loopkb_nmq_check_socket: Socket %d will NOT be offloaded", sockfd);
		}
	}
	else
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_check_socket: Error calling _loopkb_nmq_get_socket_info()");
	}

	return 0;
}

int _loopkb_nmq_socket(int sockfd, int domain, int type, int protocol)
{
	int direction = 2;
	return _loopkb_nmq_check_socket(sockfd, direction);
}

int _loopkb_nmq_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_connect: %d", sockfd);
	const int direction = 1;
	return _loopkb_nmq_check_socket(sockfd, direction);
}

int _loopkb_nmq_accept(int sockfd, const struct sockaddr *addr, socklen_t* addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_accept: %d", sockfd);
	const int direction = 0;
	return _loopkb_nmq_check_socket(sockfd, direction);
}

int _loopkb_nmq_close(int fd)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_close: %d", fd);
	_loopkb_nmq_remove_offloaded_socket(fd);
	return 0;
}

ssize_t _loopkb_nmq_receive(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
{
	/*if (src_addr != NULL && addrlen != NULL)
	{
		// This is send to, establish a new context
		_loopkb_nmq_check_socket(sockfd, 0);
	}*/

	char receive_buffer_tmp[PACKET_SIZE];
	void* receive_buffer = buf;
	if (len < PACKET_SIZE)
	{
		// When the given buffer is too small, perform a receive to a temporary buffer
		receive_buffer = receive_buffer_tmp;
	}

	if (_loopkb_nmq_is_offloaded_socket(sockfd))
	{
		const unsigned int ring_from = socket_file_map[sockfd].node_data->node_ == server_to_client_data ? client_to_server_data : server_to_client_data;
		const unsigned int ring_from_control = socket_file_map[sockfd].node_control->node_ == server_to_client_control ? client_to_server_control : server_to_client_control;
		int flags = fcntl(sockfd, F_GETFL, 0);

		size_t receive_len = PACKET_SIZE;
		if (flags & SOCK_NONBLOCK)
		{
			receive_len = PACKET_SIZE;
			if (node_recvnb(socket_file_map[sockfd].node_control, ring_from_control, buf, &receive_len))
			{
				if (receive_len == sizeof(eof) && memcmp(buf, eof, sizeof(eof)))
				{
					return -1;
				}
			}

			// Non blocking
			receive_len = PACKET_SIZE;
			if (node_recvnb(socket_file_map[sockfd].node_data, ring_from, buf, &receive_len))
			{
				len = (len < receive_len) ? len : receive_len;
				if (receive_buffer != buf)
				{
					// TODO packet can be truncated!
					memcpy(buf, receive_buffer, len);
				}
				//printf("Received non block %lu\n", receive_len);
				return len;
			}
			else
			{
				//printf("Nothing received\n");
				errno = EAGAIN;
				return 0;
			}
		}
		else
		{
			receive_len = 0;
			while (receive_len == 0)
			{
				// Blocking
				receive_len = PACKET_SIZE;
				if (node_recvnb(socket_file_map[sockfd].node_data, ring_from, receive_buffer, &receive_len))
				{
					len = (len < receive_len) ? len : receive_len;
					if (receive_buffer != buf)
					{
						// TODO packet can be truncated!
						memcpy(buf, receive_buffer, len);
					}
					return len;
				}

				receive_len = PACKET_SIZE;
				if (node_recvnb(socket_file_map[sockfd].node_control, ring_from_control, receive_buffer, &receive_len))
				{
					if (receive_len == sizeof(eof) && memcmp(receive_buffer, eof, sizeof(eof)) == 0)
					{
						return -1;
					}
				}

				receive_len = 0;
				__relax();
			}
		}
	}

	// Not offloaded
	return -1;
}

ssize_t _loopkb_nmq_send(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	/*if (dest_addr != NULL && addrlen > 0)
	{
		// This is send to, establish a new context
		_loopkb_nmq_check_socket(sockfd, 1);
	}*/

	if (_loopkb_nmq_is_offloaded_socket(sockfd))
	{
		int flags = fcntl(sockfd, F_GETFL, 0);

		const unsigned int ring_to = socket_file_map[sockfd].node_data->node_ == server_to_client_data ? client_to_server_data : server_to_client_data;
		__loopkb_log(log_level_debug, "_loopkb_nmq_send: Socket %d sending %zu bytes (from %u to %u)", sockfd, len, socket_file_map[sockfd].node_data->node_, ring_to);

		if (flags & SOCK_NONBLOCK)
		{
			if (node_sendnb(socket_file_map[sockfd].node_data, ring_to, buf, len))
			{
				return len > PACKET_SIZE ? PACKET_SIZE : len;
			}

			errno = EAGAIN;
			return 0;
		}
		else
		{
			// Blocking
			node_send(socket_file_map[sockfd].node_data, ring_to, buf, len);
			return len > PACKET_SIZE ? PACKET_SIZE : len;
		}
	}

	// Not offloaded
	return -1;
}

int merge_fds(fd_set* fdset1, const fd_set* fdset2)
{
	if (fdset2 == NULL || fdset1 == NULL)
	{
		return 0;
	}

	int retval = 0;
	for (int i = 0; i < FD_SETSIZE; ++i)
	{
		if (FD_ISSET(i, fdset2))
		{
			FD_SET(i, fdset1);
			++retval;
		}
	}
	return retval;
}

int _loopkb_nmq_select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, struct timeval *restrict timeout)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_select: %d", nfds);

	static select_function_t _sys_select = NULL;
	if (_sys_select == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_select = (select_function_t) dlsym(RTLD_NEXT, "select");
#pragma GCC diagnostic pop
	}

	int offloaded_sockets = 0;
	int total_fd_count = 0;

	for (int i = 0; i < FD_SETSIZE; ++i)
	{
		if ((readfds != NULL && FD_ISSET(i, readfds)) ||
				(writefds != NULL && FD_ISSET(i, writefds)) ||
				(exceptfds != NULL && FD_ISSET(i, exceptfds)))
		{
			if (_loopkb_nmq_is_offloaded_socket(i))
			{
				++offloaded_sockets;
			}

			++total_fd_count;
		}
	}

	__loopkb_log(log_level_debug, "_loopkb_nmq_select: select() on %d fds, out of them %d are offloaded\n", total_fd_count, offloaded_sockets);

	if (offloaded_sockets == 0)
	{
		__loopkb_log(log_level_info, "_loopkb_nmq_select: Returning _sys_select - no offloaded sockets");
		return _sys_select(nfds, readfds, writefds, exceptfds, timeout);
	}

	fd_set retval_readfds;
	fd_set retval_writefds;
	fd_set retval_exceptfds;
	FD_ZERO(&retval_readfds);
	FD_ZERO(&retval_writefds);
	FD_ZERO(&retval_exceptfds);

	fd_set select_readfds_tmp;
	fd_set select_writefds_tmp;
	fd_set select_exceptfds_tmp;

	__int64_t now_us = system_clock_us();
	__int64_t timeout_us = 0;
	if (NULL != timeout)
	{
		timeout_us = timeout->tv_sec * 1e6 + timeout->tv_usec;
	}
	const __int64_t finish_us = now_us + timeout_us;

	struct timeval sys_select_1_us;
	sys_select_1_us.tv_sec = 0;
	sys_select_1_us.tv_usec = 1;

	bool has_data = false;

	do
	{
		fd_set* sys_select_readfds = NULL;
		if (readfds != NULL)
		{
			sys_select_readfds = &select_readfds_tmp;
			memcpy(&select_readfds_tmp, readfds, sizeof(fd_set));
		}

		fd_set* sys_select_writefds = NULL;
		if (writefds != NULL)
		{
			sys_select_writefds = &select_writefds_tmp;
			memcpy(&select_writefds_tmp, writefds, sizeof(fd_set));
		}

		fd_set* sys_select_exceptfds = NULL;
		if (exceptfds != NULL)
		{
			sys_select_exceptfds = &select_exceptfds_tmp;
			memcpy(&select_exceptfds_tmp, exceptfds, sizeof(fd_set));
		}

		int sys_select_retval = _sys_select(nfds, sys_select_readfds, sys_select_writefds, sys_select_exceptfds, &sys_select_1_us);
		if (sys_select_retval > 0)
		{
			merge_fds(&retval_readfds, sys_select_readfds);
			merge_fds(&retval_writefds, sys_select_writefds);
			merge_fds(&retval_exceptfds, sys_select_exceptfds);
			has_data = true;
		}

		for (int i = 0; i < FD_SETSIZE; ++i)
		{
			if (_loopkb_nmq_is_offloaded_socket(i))
			{
				if ((readfds != NULL && FD_ISSET(i, readfds) && _loopkb_nmq_can_receive(i)))
				{
					FD_SET(i, &retval_readfds);
					has_data = true;
				}

				if ((writefds != NULL && FD_ISSET(i, writefds) && _loopkb_nmq_can_send(i)))
				{
					FD_SET(i, &retval_writefds);
					has_data = true;
				}

				// TODO Implement!
				//if ((exceptfds != NULL && FD_ISSET(i, writefds) && _loopkb_nmq_can_send(i)))
				//{
				//	FD_SET(i, &retval_exceptfds);
				//}
			}
		}

		if (has_data)
		{
			break;
		}

		now_us = system_clock_us();
	}
	while (timeout_us <= 0 || now_us <= finish_us);

	if (NULL != readfds)
	{
		memcpy(readfds, &retval_readfds, sizeof(fd_set));
	}

	if (NULL != writefds)
	{
		memcpy(writefds, &retval_writefds, sizeof(fd_set));
	}

	if (NULL != exceptfds)
	{
		memcpy(exceptfds, &retval_exceptfds, sizeof(fd_set));
	}

	int retval = 0;
	for (int i = 0; i < FD_SETSIZE; ++i)
	{
		if (readfds != NULL && FD_ISSET(i, readfds))
		{
			++retval;
		}

		if (writefds != NULL && FD_ISSET(i, writefds))
		{
			++retval;
		}

		if (exceptfds != NULL && FD_ISSET(i, exceptfds))
		{
			++retval;
		}
	}

	return retval;
}
