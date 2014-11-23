/*
 ============================================================================
 Name        : hev-socket.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socket
 ============================================================================
 */

#ifndef __HEV_SOCKET_H__
#define __HEV_SOCKET_H__

#include <stdbool.h>
#include <sys/socket.h>

typedef struct _HevSocket HevSocket;
typedef void (*HevSocketReadyCallback) (HevSocket *self, void *user_data);

HevSocket * hev_socket_new (int domain, int type, int protocol);
void hev_socket_destroy (HevSocket *self);

bool hev_socket_accept_async (HevSocket *self, struct sockaddr *addr,
			socklen_t *addr_len, HevSocketReadyCallback callback,
			void *user_data);
int hev_socket_accept_finish (HevSocket *self);

bool hev_socket_connect_async (HevSocket *self, const struct sockaddr *addr,
			socklen_t addr_len, HevSocketReadyCallback callback,
			void *user_data);
int hev_socket_connect_finish (HevSocket *self);

#endif /* __HEV_SOCKET_H__ */

