/*
 ============================================================================
 Name        : hev-dns-resolver.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2013 everyone.
 Description : Simple asyncronous DNS Resolver
 ============================================================================
 */

#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-dns-resolver.h"

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

int
hev_dns_resolver_new (void)
{
	int resolver = -1;

	resolver = socket (AF_INET, SOCK_DGRAM, 0);
	if (-1 < resolver) {
		int nonblock = 1;
		ioctl (resolver, FIONBIO, (char *) &nonblock);
	}

	return resolver;
}

bool
hev_dns_resolver_query (int resolver, const char *server, const char *domain)
{
	if (-1 < resolver) {
		ssize_t i = 0;
		uint8_t c = 0, buffer[2048];
		HevDNSHeader *header = (HevDNSHeader *) buffer;
		size_t size = strlen (domain);
		struct sockaddr_in addr;

		/* checking domain length */
		if ((2048-sizeof (HevDNSHeader)-2-4) < size)
		  return false;
		/* copy domain to queries aera */
		for (i=size-1; 0<=i; i--) {
			uint8_t b = 0;
			if ('.' == domain[i]) {
				b = c; c = 0;
			} else {
				b = domain[i]; c ++;
			}
			buffer[sizeof (HevDNSHeader)+1+i] = b;
		}
		buffer[sizeof (HevDNSHeader)] = c;
		buffer[sizeof (HevDNSHeader)+1+size] = 0;
		/* type */
		buffer[sizeof (HevDNSHeader)+1+size+1] = 0;
		buffer[sizeof (HevDNSHeader)+1+size+2] = 1;
		/* class */
		buffer[sizeof (HevDNSHeader)+1+size+3] = 0;
		buffer[sizeof (HevDNSHeader)+1+size+4] = 1;
		/* dns resolve header */
		memset (header, 0, sizeof (HevDNSHeader));
		header->id = htons (0x1234);
		header->rd = 1;
		header->qdcount = htons (1);
		/* size */
		size += sizeof (HevDNSHeader) + 6;

		memset (&addr, 0, sizeof (addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr (server);
		addr.sin_port = htons (53);
		if (0 > sendto (resolver, buffer, size,
				0, (struct sockaddr *) &addr, sizeof (addr)))
		  return false;

		return true;
	}

	return false;
}

unsigned int
hev_dns_resolver_query_finish (int resolver)
{
	if (-1 < resolver) {
		uint8_t buffer[2048];
		HevDNSHeader *header = (HevDNSHeader *) buffer;
		struct sockaddr_in addr;
		socklen_t addr_len = sizeof (addr);
		size_t i = 0, offset = sizeof (HevDNSHeader);
		unsigned int *resp = NULL;

		ssize_t size = recvfrom (resolver, buffer, 2048,
					0, (struct sockaddr *) &addr, &addr_len);
		if (53 != ntohs (addr.sin_port))
		  return 0;
		if (sizeof (HevDNSHeader) > size)
		  return 0;
		if (0 == header->ancount)
		  return 0;
		header->qdcount = ntohs (header->qdcount);
		header->ancount = ntohs (header->ancount);
		/* skip queries */
		for (i=0; i<header->qdcount; i++, offset+=4) {
			for (; offset<size;) {
				if (0 == buffer[offset]) {
					offset += 1;
					break;
				} else if (0xc0 & buffer[offset]) {
					offset += 2;
					break;
				} else {
					offset += (buffer[offset] + 1);
				}
			}
		}
		/* goto first a type answer resource area */
		for (i=0; i<header->ancount; i++) {
			for (; offset<size;) {
				if (0 == buffer[offset]) {
					offset += 1;
					break;
				} else if (0xc0 & buffer[offset]) {
					offset += 2;
					break;
				} else {
					offset += (buffer[offset] + 1);
				}
			}
			offset += 8;
			/* checking the answer is valid */
			if ((offset-7) >= size)
			  return 0;
			/* is a type */
			if ((0x00 == buffer[offset-8]) && (0x01 == buffer[offset-7]))
			  break;
			offset += 2 + (buffer[offset+1] + (buffer[offset] << 8));
		}
		/* checking resource length */
		if (((offset+5) >= size) || (0x00 != buffer[offset]) || (0x04 != buffer[offset+1]))
		  return 0;
		resp = (unsigned int *) &buffer[offset+2];

		return *resp;
	}

	return 0;
}
