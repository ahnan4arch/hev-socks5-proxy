/*
 ============================================================================
 Name        : hev-socks5-server.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 server
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-main.h"
#include "hev-socks5-server.h"
#include "hev-socks5-session.h"

#define TIMEOUT		(30 * 1000)

struct _HevSocks5Server
{
	int listen_fd;

	HevSList *session_list;
	HevEventSource *timeout_source;
	HevEventSource *listener_source;
};

static bool timeout_source_handler (void *data);
static bool listener_source_handler (HevEventSourceFD *fd, void *data);

HevSocks5Server *
hev_socks5_server_new (const char *addr, unsigned short port)
{
	HevSocks5Server *self;
	struct sockaddr_in iaddr;
	int nonblock = 1, reuseaddr = 1;

	self = hev_malloc0 (sizeof (HevSocks5Server));
	if (!self) {
		fprintf (stderr, "Malloc HevSocks5Server failed!\n");
		return NULL;
	}

	/* listen socket */
	self->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
	if (0 > self->listen_fd) {
		fprintf (stderr, "Open listen socket failed!\n");
		hev_free (self);
		return NULL;
	}
	if (0 > ioctl (self->listen_fd, FIONBIO, (char *) &nonblock)) {
		fprintf (stderr, "Set listen socket nonblock failed!\n");
		close (self->listen_fd);
		hev_free (self);
		return NULL;
	}
	if (0 > setsockopt (self->listen_fd, SOL_SOCKET, SO_REUSEADDR,
					&reuseaddr, sizeof (reuseaddr))) {
		fprintf (stderr, "Set listen socket reuse address failed!\n");
		close (self->listen_fd);
		hev_free (self);
		return NULL;
	}
	memset (&iaddr, 0, sizeof (iaddr));
	iaddr.sin_family = AF_INET;
	iaddr.sin_addr.s_addr = inet_addr (addr);
	iaddr.sin_port = htons (port);
	if ((0 > bind (self->listen_fd, (struct sockaddr *) &iaddr, sizeof (iaddr))) ||
				(0 > listen (self->listen_fd, 100))) {
		fprintf (stderr, "Bind or listen socket failed!\n");
		close (self->listen_fd);
		hev_free (self);
		return NULL;
	}

	/* event source timeout */
	self->timeout_source = hev_event_source_timeout_new (TIMEOUT);
	hev_event_source_set_priority (self->timeout_source, -1);
	hev_event_source_set_callback (self->timeout_source,
				timeout_source_handler, self, NULL);
	hev_event_loop_add_source (main_loop, self->timeout_source);
	hev_event_source_unref (self->timeout_source);

	/* event source fds for listener */
	self->listener_source = hev_event_source_fds_new ();
	hev_event_source_set_priority (self->listener_source, 1);
	hev_event_source_add_fd (self->listener_source, self->listen_fd, EPOLLIN | EPOLLET);
	hev_event_source_set_callback (self->listener_source,
				(HevEventSourceFunc) listener_source_handler, self, NULL);
	hev_event_loop_add_source (main_loop, self->listener_source);
	hev_event_source_unref (self->listener_source);

	self->session_list = NULL;

	return self;
}

void
hev_socks5_server_destroy (HevSocks5Server *self)
{
	HevSList *slist;

	for (slist=self->session_list; slist; slist=hev_slist_next (slist)) {
		HevSocks5Session *session = hev_slist_data (slist);
		hev_socks5_session_destroy (session);
	}
	hev_slist_free (self->session_list);
	hev_event_loop_del_source (main_loop, self->listener_source);
	hev_event_loop_del_source (main_loop, self->timeout_source);
	close (self->listen_fd);
	hev_free (self);
}

static bool
timeout_source_handler (void *data)
{
	HevSocks5Server *self = data;
	HevSList *slist = NULL;

	for (slist=self->session_list; slist; slist=hev_slist_next (slist)) {
		HevSocks5Session *session = hev_slist_data (slist);
		if (hev_socks5_session_get_idle (session)) {
			hev_socks5_session_destroy (session);
			hev_slist_set_data (slist, NULL);
		} else {
			hev_socks5_session_set_idle (session);
		}
	}
	self->session_list = hev_slist_remove_all (self->session_list, NULL);

	return true;
}

static void
session_close_handler (HevSocks5Session *session, void *data)
{
	HevSocks5Server *self = data;

	self->session_list = hev_slist_remove (self->session_list, session);
}

static bool
listener_source_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Server *self = data;
	HevSocks5Session *session;
	int client_fd;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof (addr);

	client_fd = accept (fd->fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
	if (0 > client_fd) {
		if (EAGAIN == errno)
		  fd->revents &= ~EPOLLIN;
		else
		  fprintf (stderr, "Accept failed!\n");

		return true;
	}

	session = hev_socks5_session_new (client_fd, session_close_handler, self);
	if (!session) {
		fprintf (stderr, "Create socks5 session failed!\n");
		close (client_fd);
		return true;
	}
	self->session_list = hev_slist_append (self->session_list, session);

	return true;
}

