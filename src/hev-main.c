/*
 ============================================================================
 Name        : hev-main.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Main
 ============================================================================
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#define __D_MAIN_LOOP__
#include "hev-main.h"
#include "hev-socks5-server.h"

HevEventLoop *main_loop;

static bool
signal_handler (void *data)
{
	HevEventLoop *loop = data;

	hev_event_loop_quit (loop);

	return false;
}

int
main (int argc, char *argv[])
{
	HevEventSource *source = NULL;
	HevSocks5Server *server = NULL;
	const char *addr = "0.0.0.0";
	unsigned short port = 1080;
	int opt;

	while (-1 != (opt = getopt (argc, argv, "a:p:"))) {
		switch (opt) {
		case 'a':
			addr = optarg;
			break;
		case 'p':
			port = atoi (optarg);
			break;
		default:
			fprintf (stderr, "%s [-a addr] [-p port]\n",
						argv[0]);
			return -1;
		}
	}

	main_loop = hev_event_loop_new ();

	signal (SIGPIPE, SIG_IGN);

	source = hev_event_source_signal_new (SIGINT);
	hev_event_source_set_priority (source, 3);
	hev_event_source_set_callback (source,
				signal_handler, main_loop, NULL);
	hev_event_loop_add_source (main_loop, source);
	hev_event_source_unref (source);

	server = hev_socks5_server_new (addr, port);
	if (server) {
		hev_event_loop_run (main_loop);
		hev_socks5_server_destroy (server);
	}

	hev_event_loop_unref (main_loop);

	return 0;
}

