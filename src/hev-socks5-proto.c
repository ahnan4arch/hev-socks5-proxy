/*
 ============================================================================
 Name        : hev-socks5-proto.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 protocol
 ============================================================================
 */

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-proto.h"

typedef struct _HevSocks5ProtoAuthReq HevSocks5ProtoAuthReq;
typedef struct _HevSocks5ProtoAuthRes HevSocks5ProtoAuthRes;
typedef struct _HevSocks5ProtoReqHeader HevSocks5ProtoReqHeader;
typedef struct _HevSocks5ProtoResHeader HevSocks5ProtoResHeader;

struct _HevSocks5ProtoAuthReq
{
	uint8_t ver;
	uint8_t method_count;
	uint8_t methods[255];
} __attribute__ ((packed));

struct _HevSocks5ProtoAuthRes
{
	uint8_t ver;
	uint8_t method;
} __attribute__ ((packed));

struct _HevSocks5ProtoReqHeader
{
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atype;
} __attribute__ ((packed));

struct _HevSocks5ProtoResHeader
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atype;
} __attribute__ ((packed));

int
hev_socks5_proto_auth_req_pack (void *buffer, uint8_t method_count,
			uint8_t *methods)
{
	HevSocks5ProtoAuthReq *req = buffer;

	req->ver = 5;
	req->method_count = method_count;
	memcpy (&req->methods, methods, method_count);

	return sizeof (2 + method_count);
}

int
hev_socks5_proto_auth_req_unpack (void *buffer, uint16_t size,
			uint8_t *method_count, uint8_t **methods)
{
	HevSocks5ProtoAuthReq *req = buffer;

	if (2 > size)
	      return 0 - (2 - size);
	if ((2 + req->method_count) > size)
	      return 0 - ((2 + req->method_count) - size);

	*method_count = req->method_count;
	*methods = req->methods;

	return 0;
}

int
hev_socks5_proto_auth_res_pack (void *buffer, uint8_t method)
{
	HevSocks5ProtoAuthRes *res = buffer;

	res->ver = 5;
	res->method = method;

	return sizeof (HevSocks5ProtoAuthRes);
}

int
hev_socks5_proto_auth_res_unpack (void *buffer, uint16_t size,
			uint8_t *method)
{
	HevSocks5ProtoAuthRes *res = buffer;

	if (sizeof (HevSocks5ProtoAuthRes) > size)
	      return 0 - (sizeof (HevSocks5ProtoAuthRes) - size);

	*method = res->method;

	return 0;
}

int
hev_socks5_proto_req_pack (void *buffer, uint8_t cmd, uint8_t atype,
			const char *addr, uint16_t port)
{
	HevSocks5ProtoReqHeader *hdr = buffer;
	void *paddr = buffer + sizeof (HevSocks5ProtoReqHeader);
	uint32_t *ipv4 = paddr;
	uint8_t *domain_len = paddr;
	uint8_t *domain = paddr + 1;
	uint16_t *pport, addr_len = 0;

	hdr->ver = 5;
	hdr->cmd = cmd;
	hdr->atype = atype;
	switch (atype) {
	case HEV_SOCKS5_PROTO_ATYPE_IPV4:
		*ipv4 = *(uint32_t *) addr;
		pport = paddr + 4;
		addr_len = 4;
		break;
	case HEV_SOCKS5_PROTO_ATYPE_DOMAIN:
		*domain_len = strlen (addr);
		memcpy (domain, addr, *domain_len);
		pport = paddr + 1 + *domain_len;
		addr_len = 1 + *domain_len;
		break;
	case HEV_SOCKS5_PROTO_ATYPE_IPV6:
		/* FIXME */
	default:
		return -1;
	}

	*pport = port;

	return sizeof (HevSocks5ProtoReqHeader) + addr_len + 2;
}

int
hev_socks5_proto_req_unpack (void *buffer, uint16_t size, uint8_t *cmd,
			uint8_t *atype, const char **addr, uint16_t *port)
{
	HevSocks5ProtoReqHeader *hdr = buffer;
	uint8_t *paddr = buffer + sizeof (HevSocks5ProtoReqHeader);
	uint8_t *domain_len = paddr;
	uint16_t *pport;

	if (sizeof (HevSocks5ProtoReqHeader) > size)
	      return 0 - (sizeof (HevSocks5ProtoReqHeader) - size);

	*cmd = hdr->cmd;
	*atype = hdr->atype;
	switch (hdr->atype) {
	case HEV_SOCKS5_PROTO_ATYPE_IPV4:
		if ((sizeof (HevSocks5ProtoReqHeader) + 4 + 2) > size)
		      return 0 - ((sizeof (HevSocks5ProtoReqHeader) + 4 + 2) - size);
		*addr = (char *) paddr;
		pport = (uint16_t *) (paddr + 4);
		break;
	case HEV_SOCKS5_PROTO_ATYPE_DOMAIN:
		if ((sizeof (HevSocks5ProtoReqHeader) + *domain_len + 2) > size)
		      return 0 - ((sizeof (HevSocks5ProtoReqHeader) + *domain_len + 2) - size);
		paddr[domain_len[0] + 1] = '\0';
		*addr = (char *) (paddr + 1);
		pport = (uint16_t *) (paddr + 1 + *domain_len);
		break;
	case HEV_SOCKS5_PROTO_ATYPE_IPV6:
		/* FIXME */
	default:
		return 0;
	}

	*port = *pport;

	return 0;
}

int
hev_socks5_proto_res_pack (void *buffer, uint8_t rep, uint8_t atype,
			const char *addr, uint16_t port)
{
	HevSocks5ProtoResHeader *hdr = buffer;
	void *paddr = buffer + sizeof (HevSocks5ProtoResHeader);
	uint32_t *ipv4 = paddr;
	uint8_t *domain_len = paddr;
	uint8_t *domain = paddr + 1;
	uint16_t *pport, addr_len = 0;

	hdr->ver = 5;
	hdr->rep = rep;
	hdr->atype = atype;
	switch (atype) {
	case HEV_SOCKS5_PROTO_ATYPE_IPV4:
		*ipv4 = *(uint32_t *) addr;
		pport = paddr + 4;
		addr_len = 4;
		break;
	case HEV_SOCKS5_PROTO_ATYPE_DOMAIN:
		*domain_len = strlen (addr);
		memcpy (domain, addr, *domain_len);
		pport = paddr + 1 + *domain_len;
		addr_len = 1 + *domain_len;
		break;
	case HEV_SOCKS5_PROTO_ATYPE_IPV6:
		/* FIXME */
	default:
		return -1;
	}

	*pport = port;

	return sizeof (HevSocks5ProtoResHeader) + addr_len + 2;
}

int
hev_socks5_proto_res_unpack (void *buffer, uint16_t size, uint8_t *rep,
			uint8_t *atype, const char **addr, uint16_t *port)
{
	HevSocks5ProtoResHeader *hdr = buffer;
	uint8_t *paddr = buffer + sizeof (HevSocks5ProtoResHeader);
	uint8_t *domain_len = paddr;
	uint16_t *pport;

	if (sizeof (HevSocks5ProtoResHeader) > size)
	      return 0 - (sizeof (HevSocks5ProtoResHeader) - size);

	*rep = hdr->rep;
	*atype = hdr->atype;
	switch (hdr->atype) {
	case HEV_SOCKS5_PROTO_ATYPE_IPV4:
		if ((sizeof (HevSocks5ProtoResHeader) + 4 + 2) > size)
		      return 0 - ((sizeof (HevSocks5ProtoReqHeader) + 4 + 2) - size);
		*addr = (char *) paddr;
		pport = (uint16_t *) (paddr + 4);
		break;
	case HEV_SOCKS5_PROTO_ATYPE_DOMAIN:
		if ((sizeof (HevSocks5ProtoResHeader) + *domain_len + 2) > size)
		      return 0 - ((sizeof (HevSocks5ProtoReqHeader) + *domain_len + 2) - size);
		paddr[domain_len[0] + 1] = '\0';
		*addr = (char *) (paddr + 1);
		pport = (uint16_t *) (paddr + 1 + *domain_len);
		break;
	case HEV_SOCKS5_PROTO_ATYPE_IPV6:
		/* FIXME */
	default:
		return 0;
	}

	*port = *pport;

	return 0;
}

