/*
 ============================================================================
 Name        : hev-dns-resolver.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Simple asyncronous DNS Resolver
 ============================================================================
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <hev-lib.h>

#include "hev-main.h"
#include "hev-pollable-fd.h"
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

struct _HevDNSResolver
{
	int fd;
	uint32_t ip;

	void *buffer;
	HevBufferList *buffer_list;
	HevPollableFD *pfd;

	HevDNSResolverReadyCallback callback;
	void *user_data;

	struct sockaddr_in raddr;
};

static ssize_t hev_dns_resolver_request_pack (uint8_t *buffer, const char *domain);
static uint32_t hev_dns_resolver_response_unpack (uint8_t *buffer, size_t size);
static ssize_t pollable_fd_reader (int fd, void *buffer, size_t count, void *user_data);
static ssize_t pollable_fd_writer (int fd, void *buffer, size_t count, void *user_data);
static void pollable_fd_read_handler (HevPollableFD *fd, void *user_data);
static void pollable_fd_write_handler (HevPollableFD *fd, void *user_data);

HevDNSResolver *
hev_dns_resolver_new (const char *server, HevBufferList *buffer_list)
{
	HevDNSResolver *self;

	self = hev_malloc0 (sizeof (HevDNSResolver));
	if (!self) {
		fprintf (stderr, "Malloc HevDNSResolver faild!\n");
		return NULL;
	}

	self->fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (!self->fd) {
		fprintf (stderr, "Open DNS socket failed!\n");
		hev_free (self);
		return NULL;
	}

	self->pfd = hev_pollable_fd_new (self->fd, 1);
	if (!self->pfd) {
		fprintf (stderr, "Open DNS pollable fd failed!\n");
		hev_free (self);
		return NULL;
	}

	self->raddr.sin_family = AF_INET;
	self->raddr.sin_addr.s_addr = inet_addr (server);
	self->raddr.sin_port = htons (53);
	self->buffer_list = buffer_list;

	return self;
}

void
hev_dns_resolver_destroy (HevDNSResolver *self)
{
	if (self->buffer)
	      hev_buffer_list_free (self->buffer_list, self->buffer);
	hev_pollable_fd_destroy (self->pfd);
	close (self->fd);
	hev_free (self);
}

bool
hev_dns_resolver_query_async (HevDNSResolver *self, const char *domain,
			HevDNSResolverReadyCallback callback, void *user_data)
{
	uint8_t *buffer;
	ssize_t size;
	HevPollableFDWriter writer;

	self->buffer = buffer = hev_buffer_list_alloc (self->buffer_list);
	if (!buffer)
	      return false;

	self->callback = callback;
	self->user_data = user_data;
	size = hev_dns_resolver_request_pack (buffer, domain);

	writer.func = pollable_fd_writer;
	writer.user_data = self;
	if (!hev_pollable_fd_write_async (self->pfd, &writer,
				buffer, size, pollable_fd_write_handler, self)) {
		hev_buffer_list_free (self->buffer_list, buffer);
		self->buffer = NULL;
		return false;
	}

	return true;
}

uint32_t
hev_dns_resolver_query_finish (HevDNSResolver *self)
{
	return self->ip;
}

static ssize_t
hev_dns_resolver_request_pack (uint8_t *buffer, const char *domain)
{
	ssize_t i = 0;
	uint8_t c = 0;
	ssize_t size = strlen (domain);
	HevDNSHeader *header = (HevDNSHeader *) buffer;

	/* checking domain length */
	if ((2048-sizeof (HevDNSHeader)-2-4) < size)
	  return -1;
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
	header->id = htons ((uintptr_t) buffer & 0xff);
	header->rd = 1;
	header->qdcount = htons (1);
	/* size */
	size += sizeof (HevDNSHeader) + 6;

	return size;
}

static uint32_t
hev_dns_resolver_response_unpack (uint8_t *buffer, size_t size)
{
	uint32_t *resp = NULL;
	size_t i = 0, offset = sizeof (HevDNSHeader);
	HevDNSHeader *header = (HevDNSHeader *) buffer;

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
	resp = (uint32_t *) &buffer[offset+2];

	return *resp;
}

static ssize_t
pollable_fd_reader (int fd, void *buffer, size_t count, void *user_data)
{
	return recvfrom (fd, buffer, count, 0, NULL, NULL);
}

static ssize_t
pollable_fd_writer (int fd, void *buffer, size_t count, void *user_data)
{
	HevDNSResolver *self = user_data;

	return sendto (fd, buffer, count, 0,
				(struct sockaddr *) &self->raddr,
				sizeof (self->raddr));
}

static void
pollable_fd_read_handler (HevPollableFD *fd, void *user_data)
{
	HevDNSResolver *self = user_data;
	void *buffer;
	ssize_t size;

	size = hev_pollable_fd_read_finish (self->pfd, &buffer);
	if (0 >= size) {
		self->ip = 0;
		self->callback (self, self->user_data);
	} else {
		self->ip = hev_dns_resolver_response_unpack (buffer, size);
		self->callback (self, self->user_data);
	}

	hev_buffer_list_free (self->buffer_list, buffer);
	self->buffer = NULL;
}

static void
pollable_fd_write_handler (HevPollableFD *fd, void *user_data)
{
	HevDNSResolver *self = user_data;
	void *buffer;
	ssize_t size;

	size = hev_pollable_fd_write_finish (self->pfd, &buffer);
	if (0 >= size) {
		self->ip = 0;
		hev_buffer_list_free (self->buffer_list, buffer);
		self->buffer = NULL;
		self->callback (self, self->user_data);
	} else {
		HevPollableFDReader reader;

		reader.func = pollable_fd_reader;
		reader.user_data = self;
		if (!hev_pollable_fd_read_async (self->pfd, &reader, buffer, 2048,
					pollable_fd_read_handler, self)) {
			self->ip = 0;
			hev_buffer_list_free (self->buffer_list, buffer);
			self->buffer = NULL;
			self->callback (self, self->user_data);
		}
	}
}

