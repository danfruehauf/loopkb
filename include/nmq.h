/*
    Copyright (C) 2010 Erik Rigtorp <erik@rigtorp.com>.
    All rights reserved.

    This file is part of NanoMQ.

    NanoMQ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NanoMQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NanoMQ.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <assert.h>
#include <string.h>

static inline void __relax()  { asm volatile ("pause":::"memory"); }
static inline void __lock()   { asm volatile ("cli" ::: "memory"); }
static inline void __unlock() { asm volatile ("sti" ::: "memory"); }
static inline void __comp()   { asm volatile ("": : :"memory"); }
static inline void __memrw()  { asm volatile ("mfence":::"memory"); }
static inline void __memr()   { asm volatile ("lfence":::"memory"); }
static inline void __memw()   { asm volatile ("sfence":::"memory"); }


// POD for header data
struct header
{
	unsigned int nodes;
	unsigned int rings;
	unsigned int size;
	size_t msg_size;
};

// POD for ring
struct ring
{
	unsigned int _size;
	size_t _msg_size;
	size_t _offset;

	char _pad1[128];
	// R/W access by the reader
	// R/O access by the writer
	volatile unsigned int _head;

	char _pad2[128];
	// R/W access by the writer
	// R/O access by the reader
	volatile unsigned int _tail;
};

struct context_t
{
	void* p_;
	size_t size_;
	struct header* header_;
	struct ring* ring_;
	char* data_;
};

// Round up to the power of two
static unsigned int context_po2(unsigned int size)
{
	unsigned int i;
	for (i = 0; (1U << i) < size; i++);
	return 1U << i;
}

struct context_t* context_create(struct context_t* context_, const char* fname, unsigned int nodes, unsigned int size, unsigned int msg_size)
{
	int fd = open(fname, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd == -1)
		return NULL;

	unsigned int real_size = context_po2(size);
	unsigned int n_rings = 2 * (nodes * (nodes - 1)) / 2;
	unsigned int file_size = sizeof(struct header) + sizeof(struct ring) * n_rings + n_rings * real_size * msg_size;

	if (ftruncate(fd, file_size) == -1)
		return NULL;

	context_->p_ = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (context_->p_ == NULL)
		return NULL;

	close(fd);
	memset(context_->p_, 0, file_size);

	context_->header_ = (struct header*) context_->p_;
	context_->ring_ = (struct ring*) (context_->header_ + 1);
	context_->data_ = (char*)(context_->ring_ + n_rings);

	context_->header_->nodes = nodes;
	context_->header_->rings = n_rings;
	context_->header_->size = real_size - 1;
	context_->header_->msg_size = msg_size + sizeof(size_t);

	for (unsigned int i = 0; i < context_->header_->rings; i++)
	{
		context_->ring_[i]._size = real_size - 1;
		context_->ring_[i]._msg_size = context_->header_->msg_size;
		context_->ring_[i]._offset = &context_->data_[i * real_size * msg_size] - context_->data_;
	}

	return context_;
}

struct context_t* context_open(struct context_t* context_, const char* fname, unsigned int nodes, unsigned int size, unsigned int msg_size)
{
	int fd = open(fname, O_RDWR);
	if (fd == -1)
		return context_create(context_, fname, nodes, size, msg_size);

	struct stat buf;
	if (fstat(fd, &buf) == -1)
		return NULL;

	unsigned int file_size = buf.st_size;
	context_->size_ = file_size;

	if (ftruncate(fd, file_size) == -1)
		return NULL;

	context_->p_ = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (context_->p_ == NULL)
		return NULL;

	context_->header_ = (struct header*) context_->p_;
	context_->ring_ = (struct ring*) (context_->header_ + 1);
	context_->data_ = (char*) (context_->ring_ + context_->header_->rings);

	return context_;
}

void context_destroy(struct context_t* context_)
{
	munmap(context_->p_, context_->size_);
}

void context_print(struct context_t* context_)
{
	printf("nodes: %u, size: %u, msgsz: %lu\n", context_->header_->nodes, context_->header_->size, context_->header_->msg_size);
	for (unsigned int i = 0; i < context_->header_->rings; i++)
	{
		printf("%3i: %10u %10u\n", i, context_->ring_[i]._head, context_->ring_[i]._tail);
	}
}

// Node pair to ring
unsigned int context_np2r(struct context_t* context_, unsigned int from, unsigned int to)
{
	assert(from != to);
	assert(from < context_->header_->nodes);
	assert(to < context_->header_->nodes);
	if (from > to)
	{
		return to * (context_->header_->nodes - 1) + from - 1;
	}
	else
	{
		return to * (context_->header_->nodes - 1) + from;
	}
}

struct ring* context_get_ring(struct context_t* context_, unsigned int from, unsigned int to)
{
	// TODO set errno and return error condition
	assert(context_->p_ != NULL);
	return &context_->ring_[context_np2r(context_, from, to)];
}

bool context_send_ring(struct context_t* context_, struct ring *ring, const void* msg, size_t size)
{
	assert(size <= (ring->_msg_size - sizeof(size_t)));

	unsigned int h = (ring->_head - 1) & ring->_size;
	unsigned int t = ring->_tail;
	if (t == h)
		return false;

	char* d = &context_->data_[context_->ring_->_offset + t * ring->_msg_size];
	memcpy(d, &size, sizeof(size));
	memcpy(d + sizeof(size), msg, size);

	// Barrier is needed to make sure that item is updated
	// before it's made available to the reader
	__memw();

	ring->_tail = (t + 1) & ring->_size;
	return true;
}

bool context_send(struct context_t* context_, unsigned int from, unsigned int to, const void* msg, size_t size)
{
	struct ring *ring = context_get_ring(context_, from, to);
	while (!context_send_ring(context_, ring, msg, size)) __relax();
	return true;
}

bool context_sendnb(struct context_t* context_, unsigned int from, unsigned int to, const void* msg, size_t size)
{
	struct ring *ring = context_get_ring(context_, from, to);
	return context_send_ring(context_, ring, msg, size);
}

bool context_recv_ring(struct context_t* context_, struct ring *ring, void* msg, size_t* size)
{
	unsigned int t = ring->_tail;
	unsigned int h = ring->_head;
	if (h == t)
		return false;

	char* d = &context_->data_[context_->ring_->_offset + h * ring->_msg_size];

	size_t recv_size;
	memcpy(&recv_size, d, sizeof(size_t));
	assert(recv_size <= *size && "buffer too small");
	*size = recv_size;
	memcpy(msg, d + sizeof(size_t), recv_size);

	// Barrier is needed to make sure that we finished reading the item
	// before moving the head
	__comp();

	ring->_head = (h + 1) & context_->ring_->_size;
	return true;
}

bool context_recv(struct context_t* context_, unsigned int from, unsigned int to, void* msg, size_t* size)
{
	struct ring *ring = context_get_ring(context_, from, to);
	while (!context_recv_ring(context_, ring, msg, size)) __relax();
	return true;
}

bool context_recvnb(struct context_t* context_, unsigned int from, unsigned int to, void* s, size_t* size)
{
	return context_recv_ring(context_, context_get_ring(context_, from, to), s, size);
}

bool context_recv_to(struct context_t* context_, unsigned int to, void* msg, size_t* size)
{
	// TODO "fair" receiving
	while (true)
	{
		for (unsigned int i = 0; i < context_->header_->nodes; i++)
		{
			if (to != i && context_recvnb(context_, i, to, msg, size)) return true;
		}
		__relax();
	}
	return false;
}

ssize_t context_recvnb_to(struct context_t* context_, unsigned int to, void* msg, size_t* size)
{
	// TODO "fair" receiving
	for (unsigned int i = 0; i < context_->header_->nodes; i++)
	{
		if (to != i && context_recvnb(context_, i, to, msg, size)) return true;
	}
	return false;
}

struct node_t
{
	struct context_t* context_;
	unsigned int node_;
};

struct node_t* node_init(struct node_t* node_, struct context_t* context_, unsigned int node)
{
	node_->context_ = context_;
	node_->node_ = node;
	return node_;
}

bool node_send(struct node_t* node_, unsigned int to, const void* msg, size_t size)
{
	return context_send(node_->context_, node_->node_, to, msg, size);
}

bool node_sendnb(struct node_t* node_, unsigned int to, const void* msg, size_t size)
{
	return context_sendnb(node_->context_, node_->node_, to, msg, size);
}

bool node_recv(struct node_t* node_, unsigned int from, void* msg, size_t* size)
{
	return context_recv(node_->context_, from, node_->node_, msg, size);
}

bool node_recvnb(struct node_t* node_, unsigned int from, void* msg, size_t* size)
{
	return context_recvnb(node_->context_, from, node_->node_, msg, size);
}

bool node_recv_to(struct node_t* node_, void* msg, size_t* size)
{
	return context_recv_to(node_->context_, node_->node_, msg, size);
}

bool node_recvnb_to(struct node_t* node_, void* msg, size_t* size)
{
	return context_recvnb_to(node_->context_, node_->node_, msg, size);
}
