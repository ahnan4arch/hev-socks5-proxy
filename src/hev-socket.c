/*
 ============================================================================
 Name        : hev-socket.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socket
 ============================================================================
 */

#include <stdio.h>
#include <hev-lib.h>

#include "hev-socket.h"

struct _HevSocket
{
	int fd;
};

HevSocket *
hev_socket_new (int domain, int type, int protocol)
{
	HevSocket *self;

	self = hev_malloc0 (sizeof (HevSocket));
	if (!self) {
		fprintf (stderr, "Malloc HevSocket failed!\n");
		return NULL;
	}

	return self;
}

void
hev_socket_destroy (HevSocket *self)
{
	hev_free (self);
}

int
hev_socket_get_fd (HevSocket *self)
{
	return self->fd;
}

bool
hev_socket_accept_async (HevSocket *self, struct sockaddr *addr,
			socklen_t *addr_len, HevSocketReadyCallback callback,
			void *user_data)
{
	return true;
}

int
hev_socket_accept_finish (HevSocket *self)
{
	return 0;
}


bool
hev_socket_connect_async (HevSocket *self, const struct sockaddr *addr,
			socklen_t addr_len, HevSocketReadyCallback callback,
			void *user_data)
{
	return true;
}

int
hev_socket_connect_finish (HevSocket *self)
{
	return 0;
}

