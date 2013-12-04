/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2013 everyone.
 Description : Socks5 session
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-session.h"

enum
{
	CLIENT_IN = (1 << 3),
	CLIENT_OUT = (1 << 2),
	REMOTE_IN = (1 << 1),
	REMOTE_OUT = (1 << 0),
};

struct _HevSocks5Session
{
	unsigned int ref_count;

	int cfd;
	int rfd;
	uint8_t revents;
	bool idle;

	HevEventSourceFD *client_fd;
	HevEventSourceFD *remote_fd;
	HevRingBuffer *forward_buffer;
	HevRingBuffer *backward_buffer;
	HevEventSource *source;

	HevSocks5SessionCloseNotify notify;
	void *notify_data;
};

static bool session_source_socks5_handler (HevEventSourceFD *fd, void *data);
static bool session_source_splice_handler (HevEventSourceFD *fd, void *data);

HevSocks5Session *
hev_socks5_session_new (int client_fd, HevSocks5SessionCloseNotify notify, void *notify_data)
{
	HevSocks5Session *self = HEV_MEMORY_ALLOCATOR_ALLOC (sizeof (HevSocks5Session));
	if (self) {
		self->ref_count = 1;
		self->cfd = client_fd;
		self->rfd = -1;
		self->idle = false;
		self->client_fd = NULL;
		self->remote_fd = NULL;
		self->forward_buffer = hev_ring_buffer_new (2000);
		self->backward_buffer = hev_ring_buffer_new (2000);
		self->source = NULL;
		self->notify = notify;
		self->notify_data = notify_data;
	}

	return self;
}

HevSocks5Session *
hev_socks5_session_ref (HevSocks5Session *self)
{
	if (self)
	  self->ref_count ++;

	return self;
}

void
hev_socks5_session_unref (HevSocks5Session *self)
{
	if (self) {
		self->ref_count --;
		if (0 == self->ref_count) {
			close (self->cfd);
			if (-1 < self->rfd)
			  close (self->rfd);
			hev_ring_buffer_unref (self->forward_buffer);
			hev_ring_buffer_unref (self->backward_buffer);
			if (self->source)
			  hev_event_source_unref (self->source);
			HEV_MEMORY_ALLOCATOR_FREE (self);
		}
	}
}

HevEventSource *
hev_socks5_session_get_source (HevSocks5Session *self)
{
	if (self) {
		if (self->source)
		  return self->source;
		self->source = hev_event_source_fds_new ();
		if (self->source) {
			int nonblock = 1;
			hev_event_source_set_callback (self->source,
						(HevEventSourceFunc) session_source_socks5_handler, self, NULL);
			ioctl (self->cfd, FIONBIO, (char *) &nonblock);
			self->client_fd = hev_event_source_add_fd (self->source, self->cfd, EPOLLIN | EPOLLOUT | EPOLLET);
		}
		return self->source;
	}

	return NULL;
}

void
hev_socks5_session_set_idle (HevSocks5Session *self)
{
	if (self)
	  self->idle = true;
}

bool
hev_socks5_session_get_idle (HevSocks5Session *self)
{
	return self ? self->idle : false;
}

static size_t
iovec_size (struct iovec *iovec, size_t iovec_len)
{
	size_t i = 0, size = 0;

	for (i=0; i<iovec_len; i++)
	  size += iovec[i].iov_len;

	return size;
}

static ssize_t
read_data (int fd, HevRingBuffer *buffer)
{
	struct msghdr mh;
	struct iovec iovec[2];
	size_t iovec_len = 0, inc_len = 0;
	ssize_t size = -2;

	iovec_len = hev_ring_buffer_writing (buffer, iovec);
	if (0 < iovec_len) {
		/* recv data */
		memset (&mh, 0, sizeof (mh));
		mh.msg_iov = iovec;
		mh.msg_iovlen = iovec_len;
		size = recvmsg (fd, &mh, 0);
		inc_len = (0 > size) ? 0 : size;
		hev_ring_buffer_write_finish (buffer, inc_len);
	}

	return size;
}

static ssize_t
write_data (int fd, HevRingBuffer *buffer)
{
	struct msghdr mh;
	struct iovec iovec[2];
	size_t iovec_len = 0, inc_len = 0;
	ssize_t size = -2;

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	if (0 < iovec_len) {
		/* send data */
		memset (&mh, 0, sizeof (mh));
		mh.msg_iov = iovec;
		mh.msg_iovlen = iovec_len;
		size = sendmsg (fd, &mh, 0);
		inc_len = (0 > size) ? 0 : size;
		hev_ring_buffer_read_finish (buffer, inc_len);
	}

	return size;
}

static bool
session_source_socks5_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;
	ssize_t size = 0;

	if ((EPOLLERR | EPOLLHUP) & fd->revents)
	  goto close_session;

	return true;

close_session:
	if (self->notify)
	  self->notify (self, self->notify_data);

	return true;
}

static bool
session_source_splice_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;
	ssize_t size = 0;

	if ((EPOLLERR | EPOLLHUP) & fd->revents)
	  goto close_session;

	if (fd == self->client_fd) {
		if (EPOLLIN & fd->revents)
		  self->revents |= CLIENT_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= CLIENT_OUT;
	} else {
		if (EPOLLIN & fd->revents)
		  self->revents |= REMOTE_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= REMOTE_OUT;
	}

	if (CLIENT_OUT & self->revents) {
		size = write_data (self->client_fd->fd, self->backward_buffer);
		if (-2 < size) {
			if (-1 == size) {
				if (EAGAIN == errno) {
					self->revents &= ~CLIENT_OUT;
					self->client_fd->revents &= ~EPOLLOUT;
				} else {
					goto close_session;
				}
			}
		} else {
			self->client_fd->revents &= ~EPOLLOUT;
		}
	}

	if (REMOTE_OUT & self->revents) {
		size = write_data (self->remote_fd->fd, self->forward_buffer);
		if (-2 < size) {
			if (-1 == size) {
				if (EAGAIN == errno) {
					self->revents &= ~REMOTE_OUT;
					self->remote_fd->revents &= ~EPOLLOUT;
				} else {
					goto close_session;
				}
			}
		} else {
			self->remote_fd->revents &= ~EPOLLOUT;
		}
	}

	if (CLIENT_IN & self->revents) {
		size = read_data (self->client_fd->fd, self->forward_buffer);
		if (-2 < size) {
			if (-1 == size) {
				if (EAGAIN == errno) {
					self->revents &= ~CLIENT_IN;
					self->client_fd->revents &= ~EPOLLIN;
				} else {
					goto close_session;
				}
			} else if (0 == size) {
				goto close_session;
			}
		} else {
			self->client_fd->revents &= ~EPOLLIN;
		}
	}

	if (REMOTE_IN & self->revents) {
		size = read_data (self->remote_fd->fd, self->backward_buffer);
		if (-2 < size) {
			if (-1 == size) {
				if (EAGAIN == errno) {
					self->revents &= ~REMOTE_IN;
					self->remote_fd->revents &= ~EPOLLIN;
				} else {
					goto close_session;
				}
			} else if (0 == size) {
				goto close_session;
			}
		} else {
			self->remote_fd->revents &= ~EPOLLIN;
		}
	}

	self->idle = false;

	return true;

close_session:
	if (self->notify)
	  self->notify (self, self->notify_data);

	return true;
}

