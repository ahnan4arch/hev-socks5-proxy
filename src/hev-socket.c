/*
 ============================================================================
 Name        : hev-socket.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socket
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <hev-lib.h>

#include "hev-main.h"
#include "hev-socket.h"

struct _HevSocket
{
	int fd;

	HevEventSource *source;

	struct {
		int res;
		struct sockaddr *addr;
		socklen_t *addr_len;
		HevSocketReadyCallback callback;
		void *user_data;
	} accept_ctx;

	struct {
		int res;
		struct sockaddr addr;
		socklen_t addr_len;
		HevSocketReadyCallback callback;
		void *user_data;
	} connect_ctx;
};

static bool source_handler (HevEventSourceFD *fd, void *data);

HevSocket *
hev_socket_new (int domain, int type, int protocol)
{
	HevSocket *self;
	int nonblock = 1;

	self = hev_malloc0 (sizeof (HevSocket));
	if (!self) {
		fprintf (stderr, "Malloc HevSocket failed!\n");
		return NULL;
	}

	self->fd = socket (domain, type, protocol);
	if (0 > self->fd) {
		fprintf (stderr, "Open socket failed!\n");
		hev_free (self);
		return NULL;
	}

	if (0 > ioctl (self->fd, FIONBIO, (char *) &nonblock)) {
		fprintf (stderr, "Set listen socket nonblock failed!\n");
		close (self->fd);
		hev_free (self);
		return NULL;
	}

	self->source = hev_event_source_fds_new ();
	hev_event_source_add_fd (self->source, self->fd, EPOLLIN | EPOLLOUT | EPOLLET);
	hev_event_source_set_callback (self->source,
				(HevEventSourceFunc) source_handler, self, NULL);
	hev_event_loop_add_source (main_loop, self->source);
	hev_event_source_unref (self->source);

	return self;
}

void
hev_socket_destroy (HevSocket *self)
{
	hev_event_loop_del_source (main_loop, self->source);
	close (self->fd);
	hev_free (self);
}

int
hev_socket_get_fd (HevSocket *self)
{
	return self->fd;
}

void
hev_socket_set_priority (HevSocket *self, int priority)
{
	hev_event_source_set_priority (self->source, priority);
}

int
hev_socket_bind (HevSocket *self, const struct sockaddr *addr,
			socklen_t addr_len)
{
	return bind (self->fd, addr, addr_len);
}

int
hev_socket_listen (HevSocket *self, int backlog)
{
	return listen (self->fd, backlog);
}

int
hev_socket_set_opt (HevSocket *self, int level, int option_name,
			const void *option_value, socklen_t option_len)
{
	return setsockopt (self->fd, level, option_name, option_value, option_len);
}

bool
hev_socket_accept_async (HevSocket *self, struct sockaddr *addr,
			socklen_t *addr_len, HevSocketReadyCallback callback,
			void *user_data)
{
	if (self->accept_ctx.callback)
	      return false;

	self->accept_ctx.callback = callback;
	self->accept_ctx.user_data = user_data;
	self->accept_ctx.res = accept (self->fd, addr, addr_len);
	if (0 <= self->accept_ctx.res || (-1 == self->accept_ctx.res && EAGAIN != errno)) {
		callback (self, user_data);
		return true;
	}

	self->accept_ctx.addr = addr;
	self->accept_ctx.addr_len = addr_len;

	return true;
}

int
hev_socket_accept_finish (HevSocket *self)
{
	if (!self->accept_ctx.callback)
	      return -1;

	self->accept_ctx.callback = NULL;

	return self->accept_ctx.res;
}


bool
hev_socket_connect_async (HevSocket *self, const struct sockaddr *addr,
			socklen_t addr_len, HevSocketReadyCallback callback,
			void *user_data)
{
	if (self->connect_ctx.callback)
	      return false;

	self->connect_ctx.callback = callback;
	self->connect_ctx.user_data = user_data;
	self->connect_ctx.res = connect (self->fd, addr, addr_len);
	if (0 <= self->connect_ctx.res || (-1 == self->connect_ctx.res && EAGAIN != errno)) {
		callback (self, user_data);
		return true;
	}

	memcpy (&self->connect_ctx.addr, addr, addr_len);
	self->connect_ctx.addr_len = addr_len;

	return true;
}

int
hev_socket_connect_finish (HevSocket *self)
{
	if (!self->connect_ctx.callback)
	      return -1;

	self->connect_ctx.callback = NULL;

	return self->connect_ctx.res;
}

static bool
source_handler (HevEventSourceFD *fd, void *data)
{
	HevSocket *self = data;

	if (EPOLLIN & fd->revents && self->accept_ctx.callback) {
		self->accept_ctx.res = accept (self->fd, self->accept_ctx.addr,
					self->accept_ctx.addr_len);
		if (0 <= self->accept_ctx.res ||
				(-1 == self->accept_ctx.res && EAGAIN != errno)) {
			self->accept_ctx.callback (self, self->accept_ctx.user_data);
		}
	}

	if (EPOLLOUT & fd->revents && self->connect_ctx.callback) {
		self->connect_ctx.res = connect (self->fd, &self->connect_ctx.addr,
					self->connect_ctx.addr_len);
		if (0 <= self->connect_ctx.res ||
				(-1 == self->connect_ctx.res && EAGAIN != errno)) {
			self->connect_ctx.callback (self, self->connect_ctx.user_data);
		}
	}

	fd->revents = 0;

	return true;
}

