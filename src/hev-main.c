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

	main_loop = hev_event_loop_new ();

	signal (SIGPIPE, SIG_IGN);

	source = hev_event_source_signal_new (SIGINT);
	hev_event_source_set_priority (source, 3);
	hev_event_source_set_callback (source,
				signal_handler, main_loop, NULL);
	hev_event_loop_add_source (main_loop, source);
	hev_event_source_unref (source);

	hev_event_loop_unref (main_loop);

	return 0;
}

