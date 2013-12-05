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

typedef struct _HevDNSHeader HevDNSHeader;

struct _HevDNSHeader
{
	uint16_t id;
	uint8_t rd : 1;
	uint8_t tc : 1;
	uint8_t aa : 1;
	uint8_t opcode : 4;
	uint8_t qr : 1;
	uint8_t rcode : 4;
	uint8_t z : 3;
	uint8_t ra : 1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));

int hev_dns_resolver_new (void);
bool hev_dns_resolver_query (int resolver, const char *server, const char *domain);
unsigned int hev_dns_resolver_query_finish (int resolver);

#endif /* __HEV_DNS_RESOLVER_H__ */

