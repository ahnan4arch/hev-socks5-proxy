/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2013 everyone.
 Description : Socks5 session
 ============================================================================
 */

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
#include "hev-dns-resolver.h"

#define DNS_SERVER	"8.8.8.8"

enum
{
	DNSRSV_IN = (1 << 4),
	CLIENT_IN = (1 << 3),
	CLIENT_OUT = (1 << 2),
	REMOTE_IN = (1 << 1),
	REMOTE_OUT = (1 << 0),
};

enum
{
	STEP_NULL,
	STEP_READ_AUTH_METHOD,
	STEP_WRITE_AUTH_METHOD,
	STEP_READ_REQUEST,
	STEP_DO_CONNECT,
	STEP_PARSE_ADDR_IPV4,
	STEP_PARSE_ADDR_DOMAIN,
	STEP_WAIT_DNS_RESOLV,
	STEP_DO_SOCKET_CONNECT,
	STEP_WAIT_SOCKET_CONNECT,
	STEP_WRITE_RESPONSE,
	STEP_DO_SPLICE,
	STEP_WRITE_RESPONSE_ERROR,
	STEP_CLOSE_SESSION,
};

struct _HevSocks5Session
{
	int cfd;
	int rfd;
	int dfd;
	unsigned int ref_count;
	unsigned int step;
	bool idle;
	uint8_t revents;
	uint8_t auth_method;
	uint8_t addr_type;
	size_t roffset;
	HevEventSourceFD *client_fd;
	HevEventSourceFD *remote_fd;
	HevRingBuffer *forward_buffer;
	HevRingBuffer *backward_buffer;
	HevEventSource *source;
	HevSocks5SessionCloseNotify notify;
	void *notify_data;
	struct sockaddr_in addr;
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
		self->dfd = -1;
		self->revents = 0;
		self->idle = false;
		self->client_fd = NULL;
		self->remote_fd = NULL;
		self->forward_buffer = hev_ring_buffer_new (2000);
		self->backward_buffer = hev_ring_buffer_new (2000);
		self->source = NULL;
		self->step = STEP_NULL;
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
			if (-1 < self->dfd)
			  close (self->dfd);
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
			self->client_fd = hev_event_source_add_fd (self->source, self->cfd,
						EPOLLIN | EPOLLOUT | EPOLLET);
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
client_read (HevSocks5Session *self)
{
	ssize_t size = read_data (self->client_fd->fd, self->forward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~CLIENT_IN;
				self->client_fd->revents &= ~EPOLLIN;
			} else {
				return false;
			}
		} else if (0 == size) {
			return false;
		}
	} else {
		self->client_fd->revents &= ~EPOLLIN;
	}

	return true;
}

static bool
client_write (HevSocks5Session *self)
{
	ssize_t size = write_data (self->client_fd->fd, self->backward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~CLIENT_OUT;
				self->client_fd->revents &= ~EPOLLOUT;
			} else {
				return false;
			}
		}
	} else {
		self->client_fd->revents &= ~EPOLLOUT;
	}

	return true;
}

static bool
remote_read (HevSocks5Session *self)
{
	ssize_t size = read_data (self->remote_fd->fd, self->backward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~REMOTE_IN;
				self->remote_fd->revents &= ~EPOLLIN;
			} else {
				return false;
			}
		} else if (0 == size) {
			return false;
		}
	} else {
		self->remote_fd->revents &= ~EPOLLIN;
	}

	return true;
}

static bool
remote_write (HevSocks5Session *self)
{
	ssize_t size = write_data (self->remote_fd->fd, self->forward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~REMOTE_OUT;
				self->remote_fd->revents &= ~EPOLLOUT;
			} else {
				return false;
			}
		}
	} else {
		self->remote_fd->revents &= ~EPOLLOUT;
	}

	return true;
}

static inline bool
socks5_read_auth_method (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t i = 0, *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->forward_buffer, iovec);
	size = iovec_size (iovec, iovec_len);
	if (2 > size)
	  return true;
	data = iovec[0].iov_base;
	if (0x05 != data[0]) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	if ((2 + data[1]) > size)
	  return true;
	/* select a auth method (no auth method only) */
	self->auth_method = 0xff;
	for (i=2; i<(2+data[1]); i++) {
		if (0 == data[i]) {
			self->auth_method = 0x00;
			break;
		}
	}
	self->roffset = 2 + data[1];
	/* write auth method to ring buffer */
	iovec_len = hev_ring_buffer_writing (self->backward_buffer, iovec);
	data = iovec[0].iov_base;
	data[0] = 0x05;
	data[1] = self->auth_method;
	hev_ring_buffer_write_finish (self->backward_buffer, 2);
	self->step = STEP_WRITE_AUTH_METHOD;

	return false;
}

static inline bool
socks5_write_auth_method (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	if (0 != iovec_len)
	  return true;
	if (0xff == self->auth_method) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	self->step = STEP_READ_REQUEST;

	return false;
}

static inline bool
socks5_read_request (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->forward_buffer, iovec);
	data = iovec[0].iov_base;
	size = iovec_size (iovec, iovec_len);
	if ((self->roffset + 4) > size)
	  return true;
	if (0x05 != data[self->roffset]) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	self->addr_type = data[self->roffset+3];
	/* check command type */
	if (0x01 != data[self->roffset+1]) {
		/* response error, not supported */
		iovec_len = hev_ring_buffer_writing (self->backward_buffer, iovec);
		data = iovec[0].iov_base;
		memset (data, 0, 10);
		data[0] = 0x05;
		data[1] = 0x07;
		data[3] = 0x01;
		hev_ring_buffer_write_finish (self->backward_buffer, 10);
		self->step = STEP_WRITE_RESPONSE_ERROR;
		return false;
	}
	self->roffset += 4;
	self->step = STEP_DO_CONNECT;

	return false;
}

static inline bool
socks5_do_connect (HevSocks5Session *self)
{
	switch (self->addr_type) {
	case 0x01: /* ipv4 */
		self->step = STEP_PARSE_ADDR_IPV4;
		break;
	case 0x03: /* domain */
		self->step = STEP_PARSE_ADDR_DOMAIN;
		break;
	default: /* not supported */
		{
			struct iovec iovec[2];
			uint8_t *data = NULL;
			hev_ring_buffer_writing (self->backward_buffer, iovec);
			data = iovec[0].iov_base;
			memset (data, 0, 10);
			data[0] = 0x05;
			data[1] = 0x08;
			data[3] = 0x01;
			hev_ring_buffer_write_finish (self->backward_buffer, 10);
			self->step = STEP_WRITE_RESPONSE_ERROR;
		}
		break;
	}

	return false;
}

static inline bool
socks5_parse_addr_ipv4 (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->forward_buffer, iovec);
	data = iovec[0].iov_base;
	size = iovec_size (iovec, iovec_len);
	if ((self->roffset + 6) > size)
	  return true;
	/* construct addr */
	memset (&self->addr, 0, sizeof (self->addr));
	self->addr.sin_family = AF_INET;
	memcpy (&self->addr.sin_addr, &data[self->roffset], 4);
	memcpy (&self->addr.sin_port, &data[self->roffset+4], 2);
	self->step = STEP_DO_SOCKET_CONNECT;

	return false;
}

static inline bool
socks5_parse_addr_domain (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->forward_buffer, iovec);
	data = iovec[0].iov_base;
	size = iovec_size (iovec, iovec_len);
	if ((self->roffset + 1) > size)
	  return true;
	if ((self->roffset + data[0] + 3) > size)
	  return true;
	data += self->roffset;
	/* construct addr */
	memset (&self->addr, 0, sizeof (self->addr));
	self->addr.sin_family = AF_INET;
	memcpy (&self->addr.sin_port, &data[data[0]+1], 2);
	data[data[0]+1] = 0x00;
	/* checking is ipv4 addr */
	self->addr.sin_addr.s_addr = inet_addr ((const char *) &data[1]);
	if (INADDR_NONE != self->addr.sin_addr.s_addr) {
		self->step = STEP_DO_SOCKET_CONNECT;
		return false;
	}
	/* dns resolv */
	if (-1 == self->dfd) {
		self->dfd = hev_dns_resolver_new ();
		hev_event_source_add_fd (self->source, self->dfd, EPOLLIN | EPOLLET);
	}
	if (!hev_dns_resolver_query (self->dfd, DNS_SERVER, (const char *) &data[1])) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	self->step = STEP_WAIT_DNS_RESOLV;
	return true;
}

static inline bool
socks5_wait_dns_resolv (HevSocks5Session *self)
{
	unsigned int addr;

	if (!(DNSRSV_IN & self->revents))
	  return true;
	addr = hev_dns_resolver_query_finish (self->dfd);
	memcpy (&self->addr.sin_addr, &addr, 4);
	/* close dns resolver */
	hev_event_source_del_fd (self->source, self->dfd);
	close (self->dfd);
	self->dfd = -1;
	self->step = STEP_DO_SOCKET_CONNECT;

	return false;
}

static inline void
socks5_write_response_addr (HevSocks5Session *self)
{
	struct iovec iovec[2];
	uint8_t *data = NULL;

	/* write response to ring buffer */
	hev_ring_buffer_writing (self->backward_buffer, iovec);
	data = iovec[0].iov_base;
	data[0] = 0x05;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x01;
	memcpy (&data[4], &self->addr.sin_addr, 4);
	memcpy (&data[8], &self->addr.sin_port, 2);
	hev_ring_buffer_write_finish (self->backward_buffer, 10);
}

static inline bool
socks5_do_socket_connect (HevSocks5Session *self)
{
	int nonblock = 1;

	self->rfd = socket (AF_INET, SOCK_STREAM, 0);
	if (-1 == self->rfd) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	ioctl (self->rfd, FIONBIO, (char *) &nonblock);
	/* add fd to source */
	if (self->source)
	  self->remote_fd = hev_event_source_add_fd (self->source,
				  self->rfd, EPOLLIN | EPOLLOUT | EPOLLET);
	/* connect to remote host */
	self->step = STEP_WAIT_SOCKET_CONNECT;
	if (0 > connect (self->rfd, (struct sockaddr *) &self->addr, sizeof (self->addr))) {
		if (EINPROGRESS != errno) {
			self->step = STEP_CLOSE_SESSION;
			return false;
		}
	} else {
		socks5_write_response_addr (self);
		self->step = STEP_WRITE_RESPONSE;
		return false;
	}

	return true;
}

static inline bool
socks5_wait_socket_connect (HevSocks5Session *self)
{
	if (!(REMOTE_OUT & self->revents))
	  return true;
	socks5_write_response_addr (self);
	self->step = STEP_WRITE_RESPONSE;

	return false;
}

static inline bool
socks5_write_response (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	if (0 != iovec_len)
	  return true;
	self->step = STEP_DO_SPLICE;

	return false;
}

static inline bool
socks5_do_splice (HevSocks5Session *self)
{
	/* clear ring buffers */
	hev_ring_buffer_reset (self->forward_buffer);
	hev_ring_buffer_reset (self->backward_buffer);
	/* switch to splice source handler */
	hev_event_source_set_callback (self->source,
				(HevEventSourceFunc) session_source_splice_handler, self, NULL);
	return true;
}

static inline bool
socks5_write_response_error (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	if (0 != iovec_len)
	  return true;
	self->step = STEP_CLOSE_SESSION;

	return false;
}

static inline void
socks5_close_session (HevSocks5Session *self)
{
}

static int
handle_socks5 (HevSocks5Session *self)
{
	bool wait = false;

	switch (self->step) {
	case STEP_NULL:
		self->step = STEP_READ_AUTH_METHOD;
	case STEP_READ_AUTH_METHOD:
		wait = socks5_read_auth_method (self);
		break;
	case STEP_WRITE_AUTH_METHOD:
		wait = socks5_write_auth_method (self);
		break;
	case STEP_READ_REQUEST:
		wait = socks5_read_request (self);
		break;
	case STEP_DO_CONNECT:
		wait = socks5_do_connect (self);
		break;
	case STEP_PARSE_ADDR_IPV4:
		wait = socks5_parse_addr_ipv4 (self);
		break;
	case STEP_PARSE_ADDR_DOMAIN:
		wait = socks5_parse_addr_domain (self);
		break;
	case STEP_WAIT_DNS_RESOLV:
		wait = socks5_wait_dns_resolv (self);
		break;
	case STEP_DO_SOCKET_CONNECT:
		wait = socks5_do_socket_connect (self);
		break;
	case STEP_WAIT_SOCKET_CONNECT:
		wait = socks5_wait_socket_connect (self);
		break;
	case STEP_WRITE_RESPONSE:
		wait = socks5_write_response (self);
		break;
	case STEP_DO_SPLICE:
		wait = socks5_do_splice (self);
		break;
	case STEP_WRITE_RESPONSE_ERROR:
		wait = socks5_write_response_error (self);
		break;
	case STEP_CLOSE_SESSION:
		socks5_close_session (self);
	default:
		return -1;
	}

	return wait ? 1 : 0;
}

static bool
session_source_socks5_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;
	int wait = -1;

	if ((EPOLLERR | EPOLLHUP) & fd->revents)
	  goto close_session;

	if (fd == self->client_fd) {
		if (EPOLLIN & fd->revents)
		  self->revents |= CLIENT_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= CLIENT_OUT;
	} else if (fd == self->remote_fd) {
		if (EPOLLIN & fd->revents)
		  self->revents |= REMOTE_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= REMOTE_OUT;
	} else {
		if (EPOLLIN & fd->revents)
		  self->revents |= DNSRSV_IN;
	}

	do {
		if (CLIENT_OUT & self->revents) {
			if (!client_write (self))
			  goto close_session;
		}
		if (CLIENT_IN & self->revents) {
			if (!client_read (self))
			  goto close_session;
		}

		/* process socks5 protocol */
		wait = handle_socks5 (self);
		if (-1 == wait)
		  goto close_session;
	} while (0 == wait);

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
		if (!client_write (self))
		  goto close_session;
	}
	if (REMOTE_OUT & self->revents) {
		if (!remote_write (self))
		  goto close_session;
	}
	if (CLIENT_IN & self->revents) {
		if (!client_read (self))
		  goto close_session;
	}
	if (REMOTE_IN & self->revents) {
		if (!remote_read (self))
		  goto close_session;
	}

	self->idle = false;

	return true;

close_session:
	if (self->notify)
	  self->notify (self, self->notify_data);

	return true;
}

