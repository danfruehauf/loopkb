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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

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

struct address_mask_t
{
	union
	{
		struct sockaddr addr;
		struct sockaddr_in6 addr6; // Largest member
		struct sockaddr_in addr4;
	};
	union
	{
		struct sockaddr mask;
		struct sockaddr_in6 mask6; // Largest member
		struct sockaddr_in mask4;
	};
};

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
