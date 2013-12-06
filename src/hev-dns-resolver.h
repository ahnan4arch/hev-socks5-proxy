/*
 ============================================================================
 Name        : hev-dns-resolver.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2013 everyone.
 Description : Simple asyncronous DNS Resolver
 ============================================================================
 */

#ifndef __HEV_DNS_RESOLVER_H__
#define __HEV_DNS_RESOLVER_H__

#include <stdint.h>
#include <stdbool.h>

int hev_dns_resolver_new (void);
bool hev_dns_resolver_query (int resolver, const char *server, const char *domain);
unsigned int hev_dns_resolver_query_finish (int resolver);

#endif /* __HEV_DNS_RESOLVER_H__ */

