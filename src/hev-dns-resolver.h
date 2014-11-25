/*
 ============================================================================
 Name        : hev-dns-resolver.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Simple asyncronous DNS Resolver
 ============================================================================
 */

#ifndef __HEV_DNS_RESOLVER_H__
#define __HEV_DNS_RESOLVER_H__

#include <stdint.h>
#include <stdbool.h>

#include "hev-buffer-list.h"

typedef struct _HevDNSResolver HevDNSResolver;
typedef void (*HevDNSResolverReadyCallback) (HevDNSResolver *self, void *user_data);

HevDNSResolver * hev_dns_resolver_new (const char *server, HevBufferList *buffer_list);
HevDNSResolver * hev_dns_resolver_ref (HevDNSResolver *self);
void hev_dns_resolver_unref (HevDNSResolver *self);

bool hev_dns_resolver_query_async (HevDNSResolver *self, const char *domain,
			HevDNSResolverReadyCallback callback, void *user_data);
uint32_t hev_dns_resolver_query_finish (HevDNSResolver *self);

#endif /* __HEV_DNS_RESOLVER_H__ */

