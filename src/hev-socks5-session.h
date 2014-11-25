/*
 ============================================================================
 Name        : hev-socks5-session.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 session
 ============================================================================
 */

#ifndef __HEV_SOCKS5_SESSION_H__
#define __HEV_SOCKS5_SESSION_H__

#include <hev-lib.h>

#include "hev-buffer-list.h"

typedef struct _HevSocks5Session HevSocks5Session;
typedef void (*HevSocks5SessionCloseNotify) (HevSocks5Session *self, void *data);

HevSocks5Session * hev_socks5_session_new (int fd, HevBufferList *buffer_list,
			HevSocks5SessionCloseNotify notify, void *notify_data);
HevSocks5Session * hev_socks5_session_ref (HevSocks5Session *self);
void hev_socks5_session_unref (HevSocks5Session *self);

void hev_socks5_session_set_idle (HevSocks5Session *self);
bool hev_socks5_session_get_idle (HevSocks5Session *self);

#endif /* __HEV_SOCKS5_SESSION_H__ */

