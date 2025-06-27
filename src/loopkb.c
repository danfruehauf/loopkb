#include <dlfcn.h>
#include <stdio.h>

#include "loopkb.h"

#define VISIBILITY_DEFAULT __attribute__((__visibility__("default")))

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
	printf("Calling socket..\n");
	return _sys_socket(domain, type, protocol);
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
	printf("Calling connect..\n");
	return _sys_connect(sockfd, addr, addrlen);
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
	printf("Calling send..\n");
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
	printf("Calling sendto..\n");
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
	printf("Calling sendmsg..\n");
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
	printf("Calling recv..\n");
	return _sys_recv(sockfd, buf, len, flags);
}

ssize_t _loopkb_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t *restrict addrlen)
{
	static recvfrom_function_t _sys_recvfrom = NULL;
	if (_sys_recvfrom == NULL)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_sys_recvfrom = (recvfrom_function_t) dlsym(RTLD_NEXT, "recvfrom");
#pragma GCC diagnostic pop
	}
	printf("Calling recvfrom..\n");
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
	printf("Calling recvmsg..\n");
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
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr *restrict src_addr, socklen_t *restrict addrlen)
{
	return _loopkb_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

VISIBILITY_DEFAULT
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return _loopkb_recvmsg(sockfd, msg, flags);
}
