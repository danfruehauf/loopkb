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
	total_channels = 4,
};

enum socket_type_t : uint8_t
{
	tcp_server = 0,
	tcp_client = 1,
	udp = 2,
	unknown = UINT8_MAX,
};

struct socket_info_t
{
	int sock;
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
		struct sockaddr addr4_2;
	};
	int protocol;
};

struct offloaded_socket_t
{
	int sockfd;
	struct context_t* context;
	enum socket_type_t type;
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
		socket_file_map[i].context = NULL;
		socket_file_map[i].type = unknown;
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
	if (NULL == socket_file_map)
	{
		free(socket_file_map);
		socket_file_map = NULL;
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
			__loopkb_log(log_level_error, "_loopkb_nmq_inet_ntop4: Error calling inet_ntop %s", strerror(errno));
			return NULL;
		}
	}

	return NULL;
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
	assert(type == tcp_server || type == tcp_client);
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
	__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Socket offloaded: #%d %d (%s) type: %d", index, sockfd, filename, type);

	if (type == 0)
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_create");
		if (context_create(socket_file_map[index].context, filename, total_channels, loopkb_ring_size, loopkb_packet_size) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Error creating context %s", strerror(errno));
			return -1;
		}
	}
	else
	{
		__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: context_open");
		int fd = open(filename, O_RDWR);
		while (fd == -1)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_add_offloaded_socket: Waiting for file to become ready at %s...", filename);
			usleep(1000000); // 1ms
			fd = open(filename, O_RDWR);
		}
		close(fd);

		if (context_open(socket_file_map[index].context, filename, total_channels, loopkb_ring_size, loopkb_packet_size) == NULL)
		{
			__loopkb_log(log_level_error, "_loopkb_nmq_add_offloaded_socket: Cannot open context %s: %s", filename, strerror(errno));
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

		const unsigned int ring_from_control = _ring_from_control(&socket_file_map[index]);
		const unsigned int ring_to_control = _ring_to_control(&socket_file_map[index]);
		context_send(socket_file_map[index].context, ring_from_control, ring_to_control, eof, sizeof(eof));

		if (socket_file_map[index].type == tcp_server)
		{
			__loopkb_log(log_level_debug, "_loopkb_nmq_remove_offloaded_socket: Removing file %s", filename);
			unlink(filename);
		}

		context_destroy(socket_file_map[index].context);
		free(socket_file_map[index].context);
		socket_file_map[index].context = NULL;
		socket_file_map[index].type = unknown;

		const int removed_index = _loopkb_nmq_remove_index(index, sockfd);
		(void) removed_index;
		assert(removed_index == index);
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
	int type = 2;
	return _loopkb_nmq_check_add_socket(sockfd, type);
}

int _loopkb_nmq_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	__loopkb_log(log_level_trace, "_loopkb_nmq_connect: %d", sockfd);
	const int type = 1;

	struct socket_info_t socket_info;
	if (_loopkb_nmq_get_socket_info_local(sockfd, &socket_info) < 0 ||
			_loopkb_nmq_get_socket_info_remote(sockfd, &socket_info, addr, addrlen))
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_connect: Error getting socket information - socket %d will not be offloaded", sockfd);
		return _sys_connect(sockfd, addr, addrlen);
	}
	// Flip type, as type == 1 (client -> server)
	_loopkb_nmq_socket_info_flip_direction(&socket_info);

	const bool offloaded = _loopkb_nmq_should_offload_socket(sockfd, &socket_info);

	if (!offloaded)
	{
		return _sys_connect(sockfd, addr, addrlen);
	}

	int flags = 0;
	if (fcntl(sockfd, F_GETFL, flags) != 0)
	{
		// Always getting here: 107 Transport endpoint is not connected)
		//__loopkb_log(log_level_error, "_loopkb_nmq_connect: fcntl/F_GETFL socket %d (%d %s), socket will not be offloaded", sockfd, errno, strerror(errno));
		//return _sys_connect(sockfd, addr, addrlen);
	}

	int orig_flags = flags;
	flags &= ~SOCK_NONBLOCK;

	if (fcntl(sockfd, F_SETFL, flags) != 0)
	{
		__loopkb_log(log_level_error, "_loopkb_nmq_connect: fcntl/F_SETFL %d, socket will not be offloaded", sockfd);
		return _sys_connect(sockfd, addr, addrlen);
	}

	const int retval = _sys_connect(sockfd, addr, addrlen);
	if (retval < 0)
	{
		return retval;
	}

	if (fcntl(sockfd, F_SETFL, orig_flags) != 0)
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
	/*if (src_addr != NULL && addrlen != NULL)
	{
		// This is send to, establish a new context
		_loopkb_nmq_check_add_socket(sockfd, 0);
	}*/

	char receive_buffer_tmp[loopkb_packet_size];
	void* receive_buffer = buf;
	if (len < loopkb_packet_size)
	{
		// When the given buffer is too small, perform a receive to a temporary buffer
		receive_buffer = receive_buffer_tmp;
	}

	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		// Flip direction for recv
		const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
		const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
		const unsigned int ring_from_control = _ring_from_control(&socket_file_map[index]);
		const unsigned int ring_to_control = _ring_to_control(&socket_file_map[index]);

		size_t receive_len = loopkb_packet_size;
		if (flags & SOCK_NONBLOCK)
		{
			receive_len = loopkb_packet_size;
			if (context_recvnb(socket_file_map[index].context, ring_from_control, ring_to_control, buf, &receive_len))
			{
				if (receive_len == sizeof(eof) && memcmp(buf, eof, sizeof(eof)))
				{
					return -1;
				}
			}

			// Non blocking
			receive_len = loopkb_packet_size;
			if (context_recvnb(socket_file_map[index].context, ring_from, ring_to, buf, &receive_len))
			{
				__loopkb_log(log_level_trace, "_loopkb_nmq_receive: Socket %d receiving %zu bytes (from %u to %u)", sockfd, receive_len, ring_from, ring_to);
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
				receive_len = loopkb_packet_size;
				if (context_recvnb(socket_file_map[index].context, ring_from, ring_to, receive_buffer, &receive_len))
				{
					__loopkb_log(log_level_trace, "_loopkb_nmq_receive: Socket %d receiving %zu bytes (from %u to %u)", sockfd, receive_len, ring_from, ring_to);
					len = (len < receive_len) ? len : receive_len;
					if (receive_buffer != buf)
					{
						// TODO packet can be truncated!
						memcpy(buf, receive_buffer, len);
					}
					return len;
				}

				receive_len = loopkb_packet_size;
				if (context_recvnb(socket_file_map[index].context, ring_from_control, ring_to_control, receive_buffer, &receive_len))
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
		_loopkb_nmq_check_add_socket(sockfd, 1);
	}*/

	const int index = _loopkb_nmq_is_offloaded_socket(sockfd);
	if (index >= 0)
	{
		const unsigned int ring_from = _ring_from_data(&socket_file_map[index]);
		const unsigned int ring_to = _ring_to_data(&socket_file_map[index]);
		__loopkb_log(log_level_trace, "_loopkb_nmq_send: Socket %d sending %zu bytes (from %u to %u)", sockfd, len, ring_from, ring_to);

		if (flags & SOCK_NONBLOCK)
		{
			if (context_sendnb(socket_file_map[index].context, ring_from, ring_to, buf, len))
			{
				return len > loopkb_packet_size ? loopkb_packet_size : len;
			}

			errno = EAGAIN;
			return 0;
		}
		else
		{
			// Blocking
			context_send(socket_file_map[index].context, ring_from, ring_to, buf, len);
			return len > loopkb_packet_size ? loopkb_packet_size : len;
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

	__loopkb_log(log_level_debug, "_loopkb_nmq_pselect: select() on %d fds, out of them %d are offloaded", total_fd_count, offloaded_sockets);

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
