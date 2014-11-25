/*
 ============================================================================
 Name        : hev-pollable-fd.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Pollable file descriptor
 ============================================================================
 */

#ifndef __HEV_POLLABLE_FD_H__
#define __HEV_POLLABLE_FD_H__

#include <stdbool.h>

typedef struct _HevPollableFD HevPollableFD;
typedef struct _HevPollableFDIO HevPollableFDReader;
typedef struct _HevPollableFDIO HevPollableFDWriter;
typedef void (*HevPollableFDReadyCallback) (HevPollableFD *self, void *user_data);
typedef ssize_t (*HevPollableFDIOFunc) (int fd, void *buffer, size_t count, void *user_data);

struct _HevPollableFDIO
{
	HevPollableFDIOFunc func;
	void *user_data;
};

HevPollableFD * hev_pollable_fd_new (int fd, int priority);
HevPollableFD * hev_pollable_fd_ref (HevPollableFD *self);
void hev_pollable_fd_unref (HevPollableFD *self);

bool hev_pollable_fd_read_async (HevPollableFD *self, HevPollableFDReader *reader,
			void *buffer, size_t count, HevPollableFDReadyCallback callback,
			void *user_data);
ssize_t hev_pollable_fd_read_finish (HevPollableFD *self, void **buffer);

bool hev_pollable_fd_write_async (HevPollableFD *self, HevPollableFDWriter *writer,
			void *buffer, size_t count, HevPollableFDReadyCallback callback,
			void *user_data);
ssize_t hev_pollable_fd_write_finish (HevPollableFD *self, void **buffer);

#endif /* __HEV_POLLABLE_FD_H__ */

