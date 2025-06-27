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
