/*
 ============================================================================
 Name        : hev-pollable-fd.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Pollable file descriptor
 ============================================================================
 */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <hev-lib.h>

#include "hev-main.h"
#include "hev-pollable-fd.h"

struct _HevPollableFD
{
	int fd;
	unsigned int ref_count;

	HevEventSource *source;

	struct {
		void *buffer;
		size_t count;
		ssize_t res_count;
		HevPollableFDReadyCallback callback;
		void *user_data;
		HevPollableFDReader reader;
	} read_ctx;

	struct {
		void *buffer;
		size_t count;
		ssize_t res_count;
		HevPollableFDReadyCallback callback;
		void *user_data;
		HevPollableFDWriter writer;
	} write_ctx;
};

static bool source_handler (HevEventSourceFD *fd, void *data);

HevPollableFD *
hev_pollable_fd_new (int fd, int priority)
{
	int nonblock = 1;
	HevPollableFD *self;

	if (0 > ioctl (fd, FIONBIO, (char *) &nonblock))
	      return NULL;

	self = hev_malloc0 (sizeof (HevPollableFD));
	if (!self)
	      return NULL;

	self->fd = fd;
	self->ref_count = 1;

	self->source = hev_event_source_fds_new ();
	hev_event_source_set_priority (self->source, priority);
	hev_event_source_add_fd (self->source, fd, EPOLLIN | EPOLLOUT | EPOLLET);
	hev_event_source_set_callback (self->source,
				(HevEventSourceFunc) source_handler, self, NULL);
	hev_event_loop_add_source (main_loop, self->source);
	hev_event_source_unref (self->source);

	return self;
}

HevPollableFD *
hev_pollable_fd_ref (HevPollableFD *self)
{
	self->ref_count ++;

	return self;
}

void
hev_pollable_fd_unref (HevPollableFD *self)
{
	self->ref_count --;
	if (0 == self->ref_count) {
		if (self->read_ctx.callback) {
			self->read_ctx.res_count = -1;
			self->read_ctx.callback (self, self->read_ctx.user_data);
		}
		if (self->write_ctx.callback) {
			self->write_ctx.res_count = -1;
			self->write_ctx.callback (self, self->write_ctx.user_data);
		}
		hev_event_loop_del_source (main_loop, self->source);
		hev_free (self);
	}
}

bool
hev_pollable_fd_read_async (HevPollableFD *self, HevPollableFDReader *reader,
			void *buffer, size_t count, HevPollableFDReadyCallback callback,
			void *user_data)
{
	if (self->read_ctx.buffer)
	      return false;

	self->read_ctx.buffer = buffer;
	self->read_ctx.res_count = reader->func (self->fd, buffer, count, reader->user_data);
	if (0 <= self->read_ctx.res_count ||
			(-1 == self->read_ctx.res_count && EAGAIN != errno)) {
		callback (self, user_data);
		return true;
	}

	self->read_ctx.count = count;
	self->read_ctx.callback = callback;
	self->read_ctx.user_data = user_data;
	self->read_ctx.reader.func = reader->func;
	self->read_ctx.reader.user_data = reader->user_data;

	return true;
}

ssize_t
hev_pollable_fd_read_finish (HevPollableFD *self, void **buffer)
{
	if (!self->read_ctx.buffer)
	      return -1;

	if (buffer)
	      *buffer = self->read_ctx.buffer;
	self->read_ctx.buffer = NULL;
	self->read_ctx.callback = NULL;

	return self->read_ctx.res_count;
}

bool
hev_pollable_fd_write_async (HevPollableFD *self, HevPollableFDWriter *writer,
			void *buffer, size_t count, HevPollableFDReadyCallback callback,
			void *user_data)
{
	if (self->write_ctx.buffer)
	      return false;

	self->write_ctx.buffer = buffer;
	self->write_ctx.res_count = writer->func (self->fd, buffer, count, writer->user_data);
	if (0 <= self->write_ctx.res_count ||
			(-1 == self->write_ctx.res_count && EAGAIN != errno)) {
		callback (self, user_data);
		return true;
	}

	self->write_ctx.count = count;
	self->write_ctx.callback = callback;
	self->write_ctx.user_data = user_data;
	self->write_ctx.writer.func = writer->func;
	self->write_ctx.writer.user_data = writer->user_data;

	return true;
}

ssize_t
hev_pollable_fd_write_finish (HevPollableFD *self, void **buffer)
{
	if (!self->write_ctx.buffer)
	      return -1;

	if (buffer)
	      *buffer = self->write_ctx.buffer;
	self->write_ctx.buffer = NULL;
	self->write_ctx.callback = NULL;

	return self->write_ctx.res_count;
}

static bool
source_handler (HevEventSourceFD *fd, void *data)
{
	HevPollableFD *self = data;
	int revents = fd->revents;

	hev_pollable_fd_ref (self);

	fd->revents = 0;
	if (EPOLLIN & revents && self->read_ctx.callback) {
		self->read_ctx.res_count = self->read_ctx.reader.func (self->fd,
					self->read_ctx.buffer, self->read_ctx.count,
					self->read_ctx.reader.user_data);
		if (0 <= self->read_ctx.res_count ||
				(-1 == self->read_ctx.res_count && EAGAIN != errno)) {
			self->read_ctx.callback (self, self->read_ctx.user_data);
		}
	}

	if (EPOLLOUT & revents && self->write_ctx.callback) {
		self->write_ctx.res_count = self->write_ctx.writer.func (self->fd,
					self->write_ctx.buffer, self->write_ctx.count,
					self->write_ctx.writer.user_data);
		if (0 <= self->write_ctx.res_count ||
				(-1 == self->write_ctx.res_count && EAGAIN != errno)) {
			self->write_ctx.callback (self, self->write_ctx.user_data);
		}
	}

	hev_pollable_fd_unref (self);

	return true;
}

