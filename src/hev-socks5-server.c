/*
 ============================================================================
 Name        : hev-socks5-server.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 server
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-main.h"
#include "hev-socket.h"
#include "hev-buffer-list.h"
#include "hev-socks5-server.h"
#include "hev-socks5-session.h"

#define TIMEOUT		(30 * 1000)

struct _HevSocks5Server
{
	HevSocket *socket;
	HevSList *session_list;
	HevBufferList *buffer_list;
	HevEventSource *timeout_source;
};

static bool timeout_source_handler (void *data);
static void socket_handler (HevSocket *socket, void *user_data);

HevSocks5Server *
hev_socks5_server_new (const char *addr, unsigned short port)
{
	HevSocks5Server *self;
	struct sockaddr_in iaddr;
	int reuseaddr = 1;

	self = hev_malloc0 (sizeof (HevSocks5Server));
	if (!self) {
		fprintf (stderr, "Malloc HevSocks5Server failed!\n");
		return NULL;
	}

	/* listen socket */
	self->socket = hev_socket_new (AF_INET, SOCK_STREAM, 0);
	if (!self->socket) {
		fprintf (stderr, "Open listen socket failed!\n");
		hev_free (self);
		return NULL;
	}
	if (0 > hev_socket_set_opt (self->socket, SOL_SOCKET, SO_REUSEADDR,
					&reuseaddr, sizeof (reuseaddr))) {
		fprintf (stderr, "Set listen socket reuse address failed!\n");
		hev_socket_destroy (self->socket);
		hev_free (self);
		return NULL;
	}
	memset (&iaddr, 0, sizeof (iaddr));
	iaddr.sin_family = AF_INET;
	iaddr.sin_addr.s_addr = inet_addr (addr);
	iaddr.sin_port = htons (port);
	if ((0 > hev_socket_bind (self->socket, (struct sockaddr *) &iaddr, sizeof (iaddr))) ||
				(0 > hev_socket_listen (self->socket, 100))) {
		fprintf (stderr, "Bind or listen socket failed!\n");
		hev_socket_destroy (self->socket);
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

	/* buffer list */
	self->buffer_list = hev_buffer_list_new (2048, 4096);
	if (!self->buffer_list) {
		fprintf (stderr, "Create buffer list failed!\n");
		hev_socket_destroy (self->socket);
		hev_free (self);
		return NULL;
	}

	self->session_list = NULL;

	hev_socket_accept_async (self->socket, NULL, NULL, socket_handler, self);

	return self;
}

void
hev_socks5_server_destroy (HevSocks5Server *self)
{
	HevSList *slist;

	for (slist=self->session_list; slist; slist=hev_slist_next (slist)) {
		HevSocks5Session *session = hev_slist_data (slist);
		if (session)
		      hev_socks5_session_destroy (session);
	}
	hev_slist_free (self->session_list);
	hev_buffer_list_destroy (self->buffer_list);
	hev_event_loop_del_source (main_loop, self->timeout_source);
	hev_socket_destroy (self->socket);
	hev_free (self);
}

static bool
timeout_source_handler (void *data)
{
	HevSocks5Server *self = data;
	HevSList *slist;

	for (slist=self->session_list; slist; slist=hev_slist_next (slist)) {
		HevSocks5Session *session = hev_slist_data (slist);
		if (session) {
			if (hev_socks5_session_get_idle (session)) {
				hev_socks5_session_destroy (session);
				hev_slist_set_data (slist, NULL);
			} else {
				hev_socks5_session_set_idle (session);
			}
		}
	}
	self->session_list = hev_slist_remove_all (self->session_list, NULL);

	return true;
}

static void
session_close_handler (HevSocks5Session *session, void *data)
{
	HevSocks5Server *self = data;
	HevSList *slist;

	for (slist=self->session_list; slist; slist=hev_slist_next (slist)) {
		if (hev_slist_data (slist) == session) {
			hev_slist_set_data (slist, NULL);
			break;
		}
	}
}

static void
socket_handler (HevSocket *socket, void *user_data)
{
	HevSocks5Server *self = user_data;
	HevSocks5Session *session;

	int client_fd = hev_socket_accept_finish (socket);
	if (0 > client_fd) {
		fprintf (stderr, "Accept failed!\n");
		return;
	}

	session = hev_socks5_session_new (client_fd, self->buffer_list,
				session_close_handler, self);
	if (!session) {
		fprintf (stderr, "Create socks5 session failed!\n");
		close (client_fd);
		return;
	}
	self->session_list = hev_slist_append (self->session_list, session);

	hev_socket_accept_async (self->socket, NULL, NULL, socket_handler, self);
}

