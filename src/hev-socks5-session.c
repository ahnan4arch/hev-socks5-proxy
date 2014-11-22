/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 session
 ============================================================================
 */

#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-session.h"

struct _HevSocks5Session
{
	bool is_idle;

	HevBufferList *buffer_list;
};

HevSocks5Session *
hev_socks5_session_new (int client_fd, HevBufferList *buffer_list,
			HevSocks5SessionCloseNotify notify, void *notify_data)
{
	HevSocks5Session *self;

	self = hev_malloc0 (sizeof (HevSocks5Session));
	if (!self) {
		fprintf (stderr, "Malloc HevSocks5Session failed!\n");
		return NULL;
	}

	self->is_idle = false;
	self->buffer_list = buffer_list;

	return self;
}

void
hev_socks5_session_destroy (HevSocks5Session *self)
{
	hev_free (self);
}

void
hev_socks5_session_set_idle (HevSocks5Session *self)
{
	self->is_idle = true;
}

bool
hev_socks5_session_get_idle (HevSocks5Session *self)
{
	return self->is_idle;
}

