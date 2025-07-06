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
#include <emmintrin.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "loopkb.h"
#include "nmq-backend.h"
#include "nmq.h"
#include "util.h"

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

static const char eof[1] = { '\0' };

enum channel_type_t : uint8_t
{
	server_to_client_data = 0,
	client_to_server_data = 1,
	server_to_client_control = 2,
	client_to_server_control = 3,

	total_channels_udp = 2,
	total_channels_tcp = 4,
};

enum socket_type_t : uint8_t
{
	tcp_server = 0,
	tcp_client = 1,
	udp = 2,
	unknown = UINT8_MAX,
};

struct offloaded_packet_t
{
	union
	{
		struct sockaddr addr;
		struct sockaddr_in6 addr6; // Largest member
		struct sockaddr_in addr4;
	};
	char data[LOOPKB_PACKET_SIZE_MAX];
};

const size_t loopkb_offloaded_packet_payload_size = sizeof(struct sockaddr_in6);

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

struct offloaded_socket_t
{
	int sockfd;
	int flags;
	struct context_t* context;
	enum socket_type_t type;
	union
	{
		struct sockaddr addr;
		struct sockaddr_in6 addr6; // Largest member
		struct sockaddr_in addr4;
	};
};

static inline unsigned int _ring_from_data(const struct offloaded_socket_t* offload_socket)
{
	return offload_socket->type == tcp_server ? server_to_client_data : client_to_server_data;
}

static inline unsigned int _ring_to_data(const struct offloaded_socket_t* offload_socket)
{
	return offload_socket->type == tcp_server ? client_to_server_data : server_to_client_data;
}

static inline unsigned int _ring_from_control(const struct offloaded_socket_t* offload_socket)
{
	return offload_socket->type == tcp_server ? server_to_client_control : client_to_server_control;
}

static inline unsigned int _ring_to_control(const struct offloaded_socket_t* offload_socket)
{
	return offload_socket->type == tcp_server ? client_to_server_control : server_to_client_control;
}

static inline uint16_t _get_port(const struct sockaddr* addr)
{
	const struct sockaddr_in* addr4 = (struct sockaddr_in*) addr;
	const struct sockaddr_in6* addr6 = (struct sockaddr_in6*) addr;

	if (addr4->sin_family == AF_INET)
	{
		return ntohs(addr4->sin_port);
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		return ntohs(addr6->sin6_port);
	}

	return 0;
}

struct offloaded_socket_t* socket_file_map = NULL;
struct offloaded_socket_t* udp_socket_destinations = NULL;

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
	if (NULL == socket_file_map)
	{
		socket_file_map = malloc(sizeof(struct offloaded_socket_t) * loopkb_max_sockets);
	}

	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		socket_file_map[i].sockfd = -1;
		socket_file_map[i].flags = 0;
		socket_file_map[i].context = NULL;
		socket_file_map[i].type = unknown;
	}

	if (NULL == udp_socket_destinations)
	{
		udp_socket_destinations = malloc(sizeof(struct offloaded_socket_t) * loopkb_max_sockets);
	}

	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		udp_socket_destinations[i].sockfd = -1;
		udp_socket_destinations[i].context = NULL;
		udp_socket_destinations[i].type = unknown;
	}

	// 127.0.0.1/8
	inet_pton(AF_INET, "127.0.0.1", &ipv4_loopback_addresses[0].ip_addr);
	inet_pton(AF_INET, "255.0.0.0", &ipv4_loopback_addresses[0].mask);
	++ipv4_loopback_addresses_count;

	// ::1/128
	inet_pton(AF_INET6, "::1", &ipv6_loopback_addresses[0].ip_addr);
	inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &ipv6_loopback_addresses[0].mask);
	++ipv6_loopback_addresses_count;
}

__attribute__((destructor))
static void _loopkb_nmq_deinit()
{
	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (socket_file_map[i].sockfd != -1)
		{
			_loopkb_nmq_remove_offloaded_socket(socket_file_map[i].sockfd);
		}
	}

	if (NULL != socket_file_map)
	{
		free(socket_file_map);
		socket_file_map = NULL;
	}

	if (NULL != udp_socket_destinations)
	{
		free(udp_socket_destinations);
		udp_socket_destinations = NULL;
	}
}

void _loopkb_nmq_socket_info_flip_direction(struct socket_info_t* socket_info)
{
	struct sockaddr_in6 tmp;
	memcpy(&tmp, &socket_info->addr6_1, sizeof(struct sockaddr_in6));
	memcpy(&socket_info->addr6_1, &socket_info->addr6_2, sizeof(struct sockaddr_in6));
	memcpy(&socket_info->addr6_2, &tmp, sizeof(struct sockaddr_in6));
}

int _loopkb_nmq_get_socket_info_local(int sockfd, struct socket_info_t* socket_info)
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
		memcpy(&socket_info->addr_1, addr4, sizeof(struct sockaddr_in));
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		memcpy(&socket_info->addr_1, addr6, sizeof(struct sockaddr_in6));
	}
	else
	{
		__loopkb_log(log_level_error, "_loopkb_get_socket_info: Unknown address family %d for socket %d", addr4->sin_family, sockfd);
		return -1;
	}

	return 0;
}

int _loopkb_nmq_get_socket_info_remote(int sockfd, struct socket_info_t* socket_info, const struct sockaddr *addr_remote, socklen_t addrlen)
{
	struct sockaddr_in6 addr;
	const struct sockaddr_in* addr4 = (struct sockaddr_in*) &addr;
	const struct sockaddr_in6* addr6 = (struct sockaddr_in6*) &addr;

	if (NULL != addr_remote && addrlen > 0)
	{
		addr4 = (struct sockaddr_in*) addr_remote;
		addr6 = (struct sockaddr_in6*) addr_remote;
	}
	else
	{
		socklen_t len = sizeof(addr);
		if (getpeername(sockfd, (struct sockaddr*) &addr, &len) != 0)
		{
			__loopkb_log(log_level_warning, "_loopkb_get_socket_info: Error calling getpeername on socket %d: %d %s", sockfd, errno, strerror(errno));
			return -1;
		}
	}

	if (addr4->sin_family == AF_INET)
	{
		memcpy(&socket_info->addr_2, addr4, sizeof(struct sockaddr_in));
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		memcpy(&socket_info->addr_2, addr6, sizeof(struct sockaddr_in6));
	}
	else
	{
		__loopkb_log(log_level_error, "_loopkb_get_socket_info: Unknown address family %d for socket %d", addr4->sin_family, sockfd);
		return -1;
	}

	return 0;
}

int _loopkb_nmq_get_socket_info(int sockfd, struct socket_info_t* socket_info, int type)
{
	if (_loopkb_nmq_get_socket_info_local(sockfd, socket_info) < 0)
	{
		return -1;
	}

	if (_loopkb_nmq_get_socket_info_remote(sockfd, socket_info, NULL, 0) < 0)
	{
		return -1;
	}

	if (type == tcp_client)
	{
		_loopkb_nmq_socket_info_flip_direction(socket_info);
	}

	return 0;
}

char* _loopkb_nmq_inet_ntop(const struct sockaddr* addr, char* retval)
{
	const struct sockaddr_in* addr4 = (const struct sockaddr_in*) addr;
	const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*) addr;

	if (addr4->sin_family == AF_INET)
	{
		if (NULL == inet_ntop(AF_INET, &addr4->sin_addr, retval, INET_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_inet_ntop: Error calling inet_ntop %s", strerror(errno));
			return NULL;
		}
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		if (NULL == inet_ntop(AF_INET6, &addr6->sin6_addr, retval, INET6_ADDRSTRLEN))
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_inet_ntop: Error calling inet_ntop %s", strerror(errno));
			return NULL;
		}
	}

	return retval;
}

void _loopkb_nmq_socket_info_debug(const struct socket_info_t* socket_info)
{
	char buffer[256];
	int len = 256;

	char ip_addr_1_str[INET6_ADDRSTRLEN];
	char ip_addr_2_str[INET6_ADDRSTRLEN];
	_loopkb_nmq_inet_ntop(&socket_info->addr_1, ip_addr_1_str);
	_loopkb_nmq_inet_ntop(&socket_info->addr_2, ip_addr_2_str);

	const uint16_t port_1 = _get_port(&socket_info->addr_1);
	const uint16_t port_2 = _get_port(&socket_info->addr_2);
	if (socket_info->addr_1.sa_family == AF_INET)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv4.%d.%s:%d:%s:%d", socket_info->protocol, ip_addr_1_str, port_1, ip_addr_2_str, port_2);
	}
	else if (socket_info->addr_1.sa_family == AF_INET6)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv6.%d.%s:%d:%s:%d", socket_info->protocol, ip_addr_1_str, port_1, ip_addr_2_str, port_2);
	}
	else
	{
		// TODO
		//snprintf(buffer, len, LOOPKB_FILE_PREFIX "%d.%d.%u:%d:%u:%d", socket_info->addr_1.sin_family, socket_info->protocol, socket_info->ipv4.ip_addr_1, port_1, socket_info->ipv4.ip_addr_2, port_2);
	}
}

const char* _loopkb_nmq_generate_filename_for_socket(int sockfd, struct socket_info_t* socket_info, int type, char* buffer, size_t len)
{
	if (NULL == socket_info)
	{
		_loopkb_nmq_get_socket_info(sockfd, socket_info, type);
	}

	char ip_addr_1_str[INET6_ADDRSTRLEN];
	char ip_addr_2_str[INET6_ADDRSTRLEN];
	_loopkb_nmq_inet_ntop(&socket_info->addr_1, ip_addr_1_str);
	_loopkb_nmq_inet_ntop(&socket_info->addr_2, ip_addr_2_str);
	const uint16_t port_1 = _get_port(&socket_info->addr_1);
	const uint16_t port_2 = _get_port(&socket_info->addr_2);

	if (socket_info->addr_1.sa_family == AF_INET)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv4.%d.%s:%d:%s:%d", socket_info->protocol, ip_addr_1_str, port_1, ip_addr_2_str, port_2);
	}
	else if (socket_info->addr_1.sa_family == AF_INET6)
	{
		snprintf(buffer, len, LOOPKB_FILE_PREFIX "ipv6.%d.%s:%d:%s:%d", socket_info->protocol, ip_addr_1_str, port_1, ip_addr_2_str, port_2);
	}
	else
	{
		// TODO
		//snprintf(buffer, len, LOOPKB_FILE_PREFIX "%d.%d.%u:%d:%u:%d", socket_info->addr_1.sin_family, socket_info->protocol, socket_info->ipv4.ip_addr_1, port_1, socket_info->ipv4.ip_addr_2, port_2);
	}

	__loopkb_log(log_level_debug, "_loopkb_nmq_generate_filename_for_socket: Socket %d will use filename %s", sockfd, buffer);
	return buffer;
}

int _loopkb_nmq_get_udp_destination_free_index(int sockfd)
{
	// TODO Lock or use atomic operation
	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (udp_socket_destinations[i].type == unknown)
		{
			udp_socket_destinations[i].sockfd = sockfd;
			udp_socket_destinations[i].type = udp;
			return i;
		}
	}

	return -1;
}

void _loopkb_nmq_remove_udp_destination(int sockfd)
{
	// TODO Lock or use atomic operation
	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (udp_socket_destinations[i].type == udp && udp_socket_destinations[i].sockfd == sockfd)
		{
			udp_socket_destinations[i].sockfd = -1;
			udp_socket_destinations[i].type = unknown;
			__loopkb_log(log_level_trace, "_loopkb_nmq_remove_udp_destination: Removing cached destination at index %zu for socket %d", i, sockfd);
		}
	}
}

int _loopkb_nmq_get_free_index(int sockfd)
{
	// TODO Lock or use atomic operation
	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (socket_file_map[i].sockfd == -1)
		{
			socket_file_map[i].sockfd = sockfd;
			return i;
		}
	}

	return -1;
}

int _loopkb_nmq_remove_index(int index, int sockfd)
{
	// TODO Lock or use atomic operation
	if (socket_file_map[index].sockfd == sockfd)
	{
		socket_file_map[index].sockfd = -1;
		return index;
	}

	return -1;
}

int _loopkb_nmq_get_index(int sockfd)
{
	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (socket_file_map[i].sockfd == sockfd)
		{
			return i;
		}
	}

	return -1;
}

int _loopkb_nmq_is_offloaded_socket(int sockfd)
{
	return _loopkb_nmq_get_index(sockfd);
}

int _loopkb_nmq_add_offloaded_socket(int sockfd, struct socket_info_t* socket_info, int type)
{
	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Adding offloaded socket: %d", sockfd);
	assert(type == tcp_server || type == tcp_client || type == udp);
	const int index = _loopkb_nmq_get_free_index(sockfd);
	if (index < 0)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Cannot offload socket %d, try increasing LOOPKB_MAX_SOCKETS", sockfd);
		return index;
	}

	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Offloaded socket %d uses index %d", sockfd, index);

	char filename[256];
	_loopkb_nmq_generate_filename_for_socket(sockfd, socket_info, type, filename, MAX_FILENAME_SIZE);
	assert(socket_file_map[index].context == NULL);
	assert(socket_file_map[index].type == unknown);
	socket_file_map[index].context = malloc(sizeof(struct context_t));
	socket_file_map[index].type = type;
	memcpy(&socket_file_map[index].addr6, &socket_info->addr6_1, sizeof(socket_file_map[index].addr6));

	char buffer[INET6_ADDRSTRLEN];
	_loopkb_nmq_inet_ntop(&socket_file_map[index].addr, buffer);
	const uint16_t port = _get_port(&socket_file_map[index].addr);
	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Socket offloaded: #%d %d (%s) type: %d, source address: %s:%d", index, sockfd, filename, type, buffer, port);

	if (type == tcp_server)
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_create");
		if (context_create(socket_file_map[index].context, filename, total_channels_tcp, loopkb_ring_size, loopkb_offloaded_packet_size) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Error creating context %s", strerror(errno));
			return -1;
		}
	}
	else if (type == tcp_client)
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_open");
		int fd = open(filename, O_RDWR);
		while (fd == -1)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Waiting for file to become ready at %s...", filename);
			usleep(1000000); // 1ms
			fd = open(filename, O_RDWR);
		}
		_sys_close(fd);

		if (context_open(socket_file_map[index].context, filename, total_channels_tcp, loopkb_ring_size, loopkb_offloaded_packet_size) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Cannot open context %s: %s", filename, strerror(errno));
			return -1;
		}
	}
	else if (type == udp)
	{
		// TODO do not create if file already exists
		int fd = open(filename, O_RDWR);
		if (fd >= 0)
		{
			_sys_close(fd);
			unlink(filename);
		}

		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_create %s", filename);
		if (context_create(socket_file_map[index].context, filename, total_channels_udp, loopkb_ring_size, loopkb_packet_size) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Error creating context %s", strerror(errno));
			return -1;
		}
	}

	const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
	const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
	const unsigned int ring_from_control = _ring_from_control(&socket_file_map[index]);
	const unsigned int ring_to_control = _ring_to_control(&socket_file_map[index]);
	__loopkb_log(log_level_info, "_loopkb_nmq_add_offloaded_socket: Socket %d uses recv %d, send %d, recv_control: %d, send_control: %d",
				 sockfd, ring_from, ring_to, ring_from_control, ring_to_control);

	return index;
}

void _loopkb_nmq_remove_offloaded_socket(int sockfd)
{
	const int index = _loopkb_nmq_get_index(sockfd);
	if (index == -1)
	{
		return;
	}

	if (socket_file_map[index].sockfd != -1)
	{
		const char* filename = socket_file_map[index].context->filename_;
		__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Removing socket %d (%s) at index %d", sockfd, filename, index);

		if (socket_file_map[index].type == tcp_server || socket_file_map[index].type == tcp_client)
		{
			const unsigned int ring_from_control = _ring_from_control(&socket_file_map[index]);
			const unsigned int ring_to_control = _ring_to_control(&socket_file_map[index]);
			if (!context_sendnb(socket_file_map[index].context, ring_from_control, ring_to_control, eof, sizeof(eof)))
			{
				__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Could not send EOF for socket %d (%s) at index %d", sockfd, filename, index);
			}
		}

		if (socket_file_map[index].type == tcp_server)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Removing file %s", filename);
			unlink(filename);
		}

		socket_file_map[index].flags = 0;
		context_destroy(socket_file_map[index].context);
		free(socket_file_map[index].context);
		socket_file_map[index].context = NULL;
		socket_file_map[index].type = unknown;

		const int removed_index = _loopkb_nmq_remove_index(index, sockfd);
		(void) removed_index;
		assert(removed_index == index);

		// Removed cached UDP destinations, if any
		_loopkb_nmq_remove_udp_destination(sockfd);
	}
	else
	{
		__loopkb_log(log_level_trace, "_loopkb_nmq_remove_offloaded_socket: Socket %d was never offloaded", sockfd);
	}
}

struct context_t* _loopkb_nmq_get_context_for_address_dgram(int sockfd, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_get_context_for_address_dgram: %d", sockfd);
	const struct sockaddr_in* addr4 = (const struct sockaddr_in*) dest_addr;
	const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*) dest_addr;

	if (dest_addr == NULL)
	{
		// Context should already be in map if dest_addr is NULL. It normally means connect() was already called
		for (size_t i = 0; i < loopkb_max_sockets; ++i)
		{
			if (udp_socket_destinations[i].type == udp && udp_socket_destinations[i].sockfd == sockfd)
			{
				return udp_socket_destinations[i].context;
			}
		}
		return NULL;
	}

	if (addr4->sin_family == AF_INET)
	{
		addrlen = sizeof(struct sockaddr_in);
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		addrlen = sizeof(struct sockaddr_in6);
	}

	for (size_t i = 0; i < loopkb_max_sockets; ++i)
	{
		if (udp_socket_destinations[i].type == udp && memcmp(dest_addr, &udp_socket_destinations[i].addr, addrlen) == 0)
		{
			return udp_socket_destinations[i].context;
		}
	}

	struct socket_info_t socket_info;
	socket_info.protocol = SOCK_DGRAM;
	if (addr4->sin_family == AF_INET)
	{
		memcpy(&socket_info.addr4_1, addr4, sizeof(socket_info.addr4_1));
		socket_info.addr4_2.sin_family = AF_INET;
		socket_info.addr4_2.sin_port = 0;
		socket_info.addr4_2.sin_addr.s_addr = INADDR_ANY;
	}
	else if (addr6->sin6_family == AF_INET6)
	{
		memcpy(&socket_info.addr6_1, addr6, sizeof(socket_info.addr6_1));
		socket_info.addr6_2.sin6_family = AF_INET6;
		socket_info.addr6_2.sin6_port = 0;
		socket_info.addr6_2.sin6_addr = in6addr_any;
	}

	const enum socket_type_t socket_type = udp;
	char filename[256];
	_loopkb_nmq_generate_filename_for_socket(sockfd, &socket_info, socket_type, filename, 256);
	struct context_t* context = NULL;

	__loopkb_log(log_level_debug, "_loopkb_nmq_get_context_for_address_dgram: context_open %s", filename);

	int fd = open(filename, O_RDWR);
	if (fd < 0)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_get_context_for_address_dgram: Could not open context file %s", filename);
		_sys_close(fd);
		return NULL;
	}

	context = malloc(sizeof(struct context_t));
	if (context_open(context, filename, total_channels_udp, loopkb_ring_size, loopkb_packet_size) == NULL)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_get_context_for_address_dgram: Cannot open context %s: %s", filename, strerror(errno));
		return NULL;
	}

	// TODO Handle cleaning up
	const int index = _loopkb_nmq_get_udp_destination_free_index(sockfd);
	memcpy(&udp_socket_destinations[index].addr, dest_addr, addrlen);
	udp_socket_destinations[index].context = context;

	char buffer[INET6_ADDRSTRLEN];
	_loopkb_nmq_inet_ntop(dest_addr, buffer);
	__loopkb_log(log_level_debug, "_loopkb_nmq_get_context_for_address_dgram: UDP destination %s:%u cached at index %d (socket %d)",
				 buffer, _get_port(dest_addr), index, sockfd);

	return context;
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

		__m128i ip_addr_128 = (__m128i) ipv6_address_mask->ip_addr;
		__m128i ip_addr_1_128 = (__m128i) ip_addr_1;
		__m128i ip_addr_2_128 = (__m128i) ip_addr_2;
		__m128i mask_128 = (__m128i) ipv6_address_mask->mask;

		__m128i ip_addr_after_mask = _mm_and_si128(ip_addr_128, mask_128);;
		__m128i ip_addr_1_after_mask = _mm_and_si128(ip_addr_1_128, mask_128);
		__m128i ip_addr_2_after_mask = _mm_and_si128(ip_addr_2_128, mask_128);;

		if (memcmp(&ip_addr_after_mask, &ip_addr_1_after_mask, sizeof(__m128i)) == 0 &&
				memcmp(&ip_addr_after_mask, &ip_addr_2_after_mask, sizeof(__m128i)) == 0)
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
		const uint16_t port_1 = _get_port(&socket_info->addr_1);
		const uint16_t port_2 = _get_port(&socket_info->addr_2);
		if (port_1 != 0 && port_2 != 0) // Avoid listening sockets
		{
			if (socket_info->addr_1.sa_family == AF_INET)
			{
				const struct sockaddr_in* addr4_1 = (struct sockaddr_in*) &socket_info->addr_1;
				const struct sockaddr_in* addr4_2 = (struct sockaddr_in*) &socket_info->addr_2;
				uint32_t ip_addr_1 = *((uint32_t*)(&addr4_1->sin_addr));
				uint32_t ip_addr_2 = *((uint32_t*)(&addr4_2->sin_addr));
				return _loopkb_nmq_should_offload_ipv4(ip_addr_1, ip_addr_2);
			}
			else if (socket_info->addr_1.sa_family == AF_INET6)
			{
				const struct sockaddr_in6* addr6_1 = (struct sockaddr_in6*) &socket_info->addr_1;
				const struct sockaddr_in6* addr6_2 = (struct sockaddr_in6*) &socket_info->addr_2;
				__uint128_t ip_addr_1 = *((__uint128_t*)(&addr6_1->sin6_addr));
				__uint128_t ip_addr_2 = *((__uint128_t*)(&addr6_2->sin6_addr));
				return _loopkb_nmq_should_offload_ipv6(ip_addr_1, ip_addr_2);
			}
		}
	}

	return false;
}

bool _loopkb_nmq_can_send(int sockfd)
{
	// TODO Not super efficient, as it is being called from poll/select and will search the whole array every time
	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
		const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
		return context_can_send(socket_file_map[index].context, ring_from, ring_to);
	}

	return false;
}

bool _loopkb_nmq_can_receive(int sockfd)
{
	// TODO Not super efficient, as it is being called from poll/select and will search the whole array every time
	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
		const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
		return context_can_recv(socket_file_map[index].context, ring_from, ring_to);
	}

	return false;
}

int _loopkb_nmq_check_add_socket(int sockfd, int type)
{
	struct socket_info_t socket_info;
	if (_loopkb_nmq_get_socket_info(sockfd, &socket_info, type) >= 0)
	{
		if (_loopkb_nmq_should_offload_socket(sockfd, &socket_info) != 0)
		{
			__loopkb_log(log_level_info, "_loopkb_nmq_check_add_socket: Socket %d will be offloaded", sockfd);
			return _loopkb_nmq_add_offloaded_socket(sockfd, &socket_info, type);
		}
		else
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_check_add_socket: Socket %d will NOT be offloaded", sockfd);
		}
	}
	else
	{
		__loopkb_log(log_level_warning, "_loopkb_nmq_check_add_socket: Error calling _loopkb_nmq_get_socket_info()");
	}

	return -1;
}

int _loopkb_nmq_socket(int sockfd, int domain, int type_, int protocol)
{
	int type = unknown;
	return _loopkb_nmq_check_add_socket(sockfd, type);
}

int _loopkb_nmq_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct socket_info_t socket_info;
	if (_loopkb_nmq_get_socket_info_local(sockfd, &socket_info) >= 0)
	{
		if (socket_info.protocol == SOCK_DGRAM)
		{
			if (socket_info.addr_1.sa_family == AF_INET)
			{
				socket_info.addr4_2.sin_family = AF_INET;
				socket_info.addr4_2.sin_port = 0;
				socket_info.addr4_2.sin_addr.s_addr = INADDR_ANY;
			}
			else if (socket_info.addr_1.sa_family == AF_INET6)
			{
				socket_info.addr6_2.sin6_family = AF_INET6;
				socket_info.addr6_2.sin6_port = 0;
				socket_info.addr6_2.sin6_addr = in6addr_any;
			}

			enum socket_type_t type = udp;
			if (_loopkb_nmq_add_offloaded_socket(sockfd, &socket_info, type) < 0)
			{
				// TODO
				__loopkb_log(log_level_error, "_loopkb_nmq_bind: Error offloading UDP socket %d (port %d)", sockfd, 0);
				return -1;
			}
		}
	}

	return 0;
}

int _loopkb_nmq_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_connect: %d", sockfd);
	enum socket_type_t type = tcp_client;

	struct socket_info_t socket_info;
	if (_loopkb_nmq_get_socket_info_local(sockfd, &socket_info) < 0 ||
			_loopkb_nmq_get_socket_info_remote(sockfd, &socket_info, addr, addrlen))
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_connect: Error getting socket information - socket %d will not be offloaded", sockfd);
		return _sys_connect(sockfd, addr, addrlen);
	}

	if (type == tcp_client || type == udp)
	{
		// Flip direction, as this is a tcp_client, so the server address will be in addr_1
		_loopkb_nmq_socket_info_flip_direction(&socket_info);
	}

	const bool offloaded = _loopkb_nmq_should_offload_socket(sockfd, &socket_info);

	if (socket_info.protocol == SOCK_DGRAM)
	{
		// Cache context for future use
		_loopkb_nmq_get_context_for_address_dgram(sockfd, addr, addrlen);
		type = udp;
		return 0;
	}

	if (!offloaded)
	{
		return _sys_connect(sockfd, addr, addrlen);
	}

	int flags = 0;
	flags = _sys_fcntl(sockfd, F_GETFL, flags);
	int orig_flags = flags;
	flags &= ~SOCK_NONBLOCK;

	if (_sys_fcntl(sockfd, F_SETFL, flags) != 0)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_connect: fcntl/F_SETFL %d, socket will not be offloaded", sockfd);
		return _sys_connect(sockfd, addr, addrlen);
	}

	const int retval = _sys_connect(sockfd, addr, addrlen);
	if (retval < 0)
	{
		return retval;
	}

	if (_sys_fcntl(sockfd, F_SETFL, orig_flags) != 0)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_connect: fcntl/F_SETFL %d", sockfd);
		return -1;
	}

	if (_loopkb_nmq_add_offloaded_socket(sockfd, &socket_info, type) < 0)
	{
		return -1;
	}

	return retval;
}

int _loopkb_nmq_accept(int sockfd, const struct sockaddr *addr, socklen_t* addrlen, int flags)
{
	// TODO Consider flags
	__loopkb_log(log_level_trace, "_loopkb_nmq_accept: %d", sockfd);
	const int type = 0;
	return _loopkb_nmq_check_add_socket(sockfd, type);
}

int _loopkb_nmq_close(int fd)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_close: %d", fd);
	_loopkb_nmq_remove_offloaded_socket(fd);
	return 0;
}

ssize_t _loopkb_nmq_receive(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
{
	// TODO Support MSG_DONTWAIT
	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		flags = socket_file_map[index].flags | flags;

		// Flip direction for recv
		const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
		const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
		const unsigned int ring_from_control = _ring_from_control(&socket_file_map[index]);
		const unsigned int ring_to_control = _ring_to_control(&socket_file_map[index]);

		struct offloaded_packet_t offloaded_packet;
		size_t receive_len = sizeof(struct offloaded_packet_t);

		bool peek = flags & MSG_PEEK;
		bool non_blocking = flags & SOCK_NONBLOCK;

		receive_len = 0;
		while (receive_len == 0)
		{
			receive_len = sizeof(offloaded_packet);
			if (context_recvnb(socket_file_map[index].context, ring_from_control, ring_to_control, &offloaded_packet.data, &receive_len, peek))
			{
				if (receive_len == sizeof(eof) && memcmp(&offloaded_packet.data, eof, sizeof(eof)) == 0)
				{
					return -1;
				}
			}

			receive_len = sizeof(offloaded_packet);
			if (context_recvnb(socket_file_map[index].context, ring_from, ring_to, &offloaded_packet, &receive_len, peek))
			{
				__loopkb_log(log_level_trace, "_loopkb_nmq_receive: Socket %d receiving %zu bytes (from %u to %u)", sockfd, receive_len, ring_from, ring_to);
				size_t packet_len = receive_len - sizeof(offloaded_packet.addr6);
				if (receive_len <= sizeof(offloaded_packet.addr6))
				{
					__loopkb_log(log_level_error, "_loopkb_nmq_receive: receive_len %zu <= %zu sizeof(offloaded_packet.addr6)", receive_len, sizeof(offloaded_packet.addr6));
					packet_len = 0;
					return packet_len;
				}
				memcpy(buf, &offloaded_packet.data, packet_len);

				if (src_addr != NULL)
				{
					// TODO Calculate addrlen_ correctly
					size_t addrlen_ = sizeof(offloaded_packet.addr6);
					memcpy(src_addr, &offloaded_packet.addr, addrlen_);
					*addrlen = addrlen_;
				}

				//printf("Received block %lu\n", receive_len);
				return packet_len;
			}
			else
			{
				if (non_blocking)
				{
					errno = EAGAIN;
					return 0;
				}
			}

			receive_len = 0;
			__relax();
		}
	}

	// Not offloaded
	return -1;
}

ssize_t _loopkb_nmq_send(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		flags = socket_file_map[index].flags | flags;

		// TODO Avoid the memcpy
		const struct offloaded_socket_t* offloaded_socket = &socket_file_map[index];
		struct offloaded_packet_t offloaded_packet;
		memcpy(&offloaded_packet, &offloaded_socket->addr6, sizeof(offloaded_socket->addr6));
		memcpy(&offloaded_packet.data, buf, len);

		if (socket_file_map[index].type == tcp_server || socket_file_map[index].type == tcp_client)
		{
			return _loopkb_nmq_send_offload_stream(index, sockfd, buf, len, flags, dest_addr, addrlen);
		}
		else if (socket_file_map[index].type == udp)
		{
			return _loopkb_nmq_send_offload_dgram(index, sockfd, buf, len, flags, dest_addr, addrlen);
		}
	}

	return -1;
}

ssize_t _loopkb_nmq_send_offload_stream(int index, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	// TODO Avoid the memcpy
	const struct offloaded_socket_t* offloaded_socket = &socket_file_map[index];
	struct offloaded_packet_t offloaded_packet;
	memcpy(&offloaded_packet, &offloaded_socket->addr6, sizeof(offloaded_socket->addr6));
	memcpy(&offloaded_packet.data, buf, len);
	size_t packet_len = sizeof(offloaded_packet.addr6) + len;

	const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
	const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
	__loopkb_log(log_level_trace, "_loopkb_nmq_send_offload_stream: Socket %d sending %zu bytes (from %u to %u)", sockfd, len, ring_from, ring_to);

	flags = flags | socket_file_map[index].flags;
	bool non_blocking = flags & SOCK_NONBLOCK;

	if (non_blocking)
	{
		if (context_sendnb(socket_file_map[index].context, ring_from, ring_to, &offloaded_packet, packet_len))
		{
			return len > loopkb_packet_size ? loopkb_packet_size : len;
		}

		errno = EAGAIN;
		return 0;
	}
	else
	{
		// Blocking
		context_send(socket_file_map[index].context, ring_from, ring_to, &offloaded_packet, packet_len);
		return len > loopkb_packet_size ? loopkb_packet_size : len;
	}
}

ssize_t _loopkb_nmq_send_offload_dgram(int index, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	const unsigned int ring_from = server_to_client_data;
	const unsigned int ring_to = client_to_server_data;
	__loopkb_log(log_level_trace, "_loopkb_nmq_send_offload_dgram: Socket %d sending %zu bytes (from %u to %u)", sockfd, len, ring_from, ring_to);

	struct context_t* context = _loopkb_nmq_get_context_for_address_dgram(sockfd, dest_addr, addrlen);
	if (NULL == context)
	{
		return -1;
	}

	// TODO Avoid the memcpy
	const struct offloaded_socket_t* offloaded_socket = &socket_file_map[index];
	struct offloaded_packet_t offloaded_packet;
	memcpy(&offloaded_packet, &offloaded_socket->addr6, sizeof(offloaded_socket->addr6));
	memcpy(&offloaded_packet.data, buf, len);
	size_t packet_len = sizeof(offloaded_packet.addr6) + len;
	__loopkb_log(log_level_trace, "_loopkb_nmq_send: Socket %d sending %zu bytes (from %u to %u)", sockfd, len, ring_from, ring_to);

	flags = flags | socket_file_map[index].flags;
	bool non_blocking = flags & SOCK_NONBLOCK;

	if (non_blocking)
	{
		if (context_sendnb(context, ring_from, ring_to, &offloaded_packet, packet_len))
		{
			return len > loopkb_packet_size ? loopkb_packet_size : len;
		}

		errno = EAGAIN;
		return 0;
	}
	else
	{
		// Blocking
		context_send(context, ring_from, ring_to, &offloaded_packet, packet_len);
		return len > loopkb_packet_size ? loopkb_packet_size : len;
	}
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

int _loopkb_nmq_pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, const struct timespec *restrict timeout, const sigset_t* restrict sigmask)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_pselect: %d", nfds);

	int offloaded_sockets = 0;
	int total_fd_count = 0;

	for (int i = 0; i < FD_SETSIZE; ++i)
	{
		if ((readfds != NULL && FD_ISSET(i, readfds)) ||
				(writefds != NULL && FD_ISSET(i, writefds)) ||
				(exceptfds != NULL && FD_ISSET(i, exceptfds)))
		{
			if (_loopkb_nmq_is_offloaded_socket(i) >= 0)
			{
				++offloaded_sockets;
			}

			++total_fd_count;
		}
	}

	__loopkb_log(log_level_trace, "_loopkb_nmq_pselect: select() on %d fds, out of them %d are offloaded", total_fd_count, offloaded_sockets);

	if (offloaded_sockets == 0)
	{
		__loopkb_log(log_level_info, "_loopkb_nmq_pselect: Returning _sys_select - no offloaded sockets");
#ifdef _GNU_SOURCE
		return _sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
#else
		if (NULL == timeout)
		{
			return _sys_select(nfds, readfds, writefds, exceptfds, NULL);
		}
		else
		{
			struct timeval tv;
			tv.tv_sec = timeout->tv_sec;
			tv.tv_usec = timeout->tv_nsec * 1000;
			return _sys_select(nfds, readfds, writefds, exceptfds, &tv);
		}
#endif
	}

	sigset_t sigmask_prev;
	if (NULL != sigmask)
	{
		sigprocmask(SIG_SETMASK, sigmask, &sigmask_prev);
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

	__int64_t now_ns = system_clock_ns();
	__int64_t timeout_ns = 0;
	if (NULL != timeout)
	{
		timeout_ns = timeout->tv_sec * 1e9 + timeout->tv_nsec;
	}
	const __int64_t finish_ns = now_ns + timeout_ns;

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

		// Do not use sigmask here, as we manage it from outside of pselect()
#ifdef _GNU_SOURCE
		struct timespec sys_select_1_ns;
		sys_select_1_ns.tv_sec = 0;
		sys_select_1_ns.tv_nsec = 1;
		int sys_select_retval = _sys_pselect(nfds, sys_select_readfds, sys_select_writefds, sys_select_exceptfds, &sys_select_1_ns, NULL);
#else
		struct timeval sys_select_1_us;
		sys_select_1_us.tv_sec = 0;
		sys_select_1_us.tv_usec = 1;
		int sys_select_retval = _sys_select(nfds, sys_select_readfds, sys_select_writefds, sys_select_exceptfds, &sys_select_1_us);
#endif
		if (sys_select_retval > 0)
		{
			merge_fds(&retval_readfds, sys_select_readfds);
			merge_fds(&retval_writefds, sys_select_writefds);
			merge_fds(&retval_exceptfds, sys_select_exceptfds);
			has_data = true;
		}

		for (int i = 0; i < FD_SETSIZE; ++i)
		{
			if (_loopkb_nmq_is_offloaded_socket(i) >= 0)
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

		now_ns = system_clock_ns();
	}
	while (timeout_ns <= 0 || now_ns <= finish_ns);

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

	if (NULL != sigmask)
	{
		sigprocmask(SIG_SETMASK, &sigmask_prev, NULL);
	}

	return retval;
}

int _loopkb_nmq_ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_ppoll: %d", nfds);

	int offloaded_sockets = 0;
	int total_fd_count = 0;

	for (size_t i = 0; i < nfds; ++i)
	{
		if (fds[i].events & POLLIN ||
				fds[i].events & POLLOUT ||
				fds[i].events & POLLERR)
		{
			if (_loopkb_nmq_is_offloaded_socket(i))
			{
				++offloaded_sockets;
			}

			++total_fd_count;
		}
	}

	__loopkb_log(log_level_debug, "_loopkb_nmq_ppoll: ppoll() on %d fds, out of them %d are offloaded\n", total_fd_count, offloaded_sockets);

	if (offloaded_sockets == 0)
	{
		__loopkb_log(log_level_info, "_loopkb_nmq_ppoll: Returning _sys_ppoll - no offloaded sockets");
#ifdef _GNU_SOURCE
		return _sys_ppoll(fds, nfds, tmo_p, sigmask);
#else
		int timeout = tmo_p->tv_sec * 1000 + tmo_p->tv_nsec * 1000000;
		return _sys_poll(fds, nfds, timeout);
#endif
	}

	sigset_t sigmask_prev;
	if (NULL != sigmask)
	{
		sigprocmask(SIG_SETMASK, sigmask, &sigmask_prev);
	}

	__int64_t now_ns = system_clock_ns();
	__int64_t timeout_ns = 0;
	if (NULL != tmo_p)
	{
		timeout_ns = tmo_p->tv_sec * 1e9 + tmo_p->tv_nsec;
	}
	const __int64_t finish_ns = now_ns + timeout_ns;

	bool has_data = false;

	do
	{
#ifdef _GNU_SOURCE
		struct timespec sys_ppoll_1_ns;
		sys_ppoll_1_ns.tv_sec = 0;
		sys_ppoll_1_ns.tv_nsec = 1;
		int sys_ppoll_retval = _sys_ppoll(fds, nfds, &sys_ppoll_1_ns, sigmask);
#else
		const int timeout_milliseconds = 1;
		int sys_ppoll_retval = _sys_poll(fds, nfds, timeout_milliseconds);
#endif
		if (sys_ppoll_retval > 0)
		{
			has_data = true;
		}

		for (size_t i = 0; i < nfds; ++i)
		{
			if (_loopkb_nmq_is_offloaded_socket(i))
			{
				if (fds[i].events & POLLIN && _loopkb_nmq_can_receive(i))
				{
					fds[i].revents |= POLLIN;
					has_data = true;
				}

				if (fds[i].events & POLLOUT && _loopkb_nmq_can_send(i))
				{
					fds[i].revents |= POLLOUT;
					has_data = true;
				}

				// TODO Handle POLLHUP when socket is disconnected
			}
		}

		if (has_data)
		{
			break;
		}

		now_ns = system_clock_ns();
	}
	while (timeout_ns <= 0 || now_ns <= finish_ns);

	int retval = 0;
	for (size_t i = 0; i < nfds; ++i)
	{
		if (fds[i].revents > 0)
		{
			++retval;
		}
	}

	if (NULL != sigmask)
	{
		sigprocmask(SIG_SETMASK, &sigmask_prev, NULL);
	}

	return retval;
}

int _loopkb_nmq_fcntl64(int fd, int op, int arg)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_fcntl64: fd %d op %d arg %d", fd, op, arg);
	const int index = _loopkb_nmq_is_offloaded_socket(fd);
	if (index < 0)
	{
		return -1;
	}

	switch (op)
	{
	case F_SETFL:
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_fcntl64: fd %d op %d F_SETFL %d", fd, op, arg);
		socket_file_map[index].flags = arg;
		return 0;
	}
	case F_GETFL:
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_fcntl64: fd %d op %d F_GETFL %d", fd, op, socket_file_map[index].flags);
		return socket_file_map[index].flags;
	}
	default:
	{
		return -1;
	}
	} // switch

	return -1;
}
