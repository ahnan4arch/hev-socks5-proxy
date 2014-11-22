/*
 ============================================================================
 Name        : hev-socks5-server.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 server
 ============================================================================
 */

#ifndef __HEV_SOCKS5_SERVER_H__
#define __HEV_SOCKS5_SERVER_H__

#include <hev-lib.h>

typedef struct _HevSocks5Server HevSocks5Server;

HevSocks5Server * hev_socks5_server_new (const char *addr, unsigned short port);
void hev_socks5_server_destroy (HevSocks5Server *self);

#endif /* __HEV_SOCKS5_SERVER_H__ */

