/*
 ============================================================================
 Name        : hev-socks5-proto.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 protocol
 ============================================================================
 */

#ifndef __HEV_SOCKS5_PROTO_H__
#define __HEV_SOCKS5_PROTO_H__

#include <stdint.h>

typedef enum _HevSocks5ProtoMethods HevSocks5ProtoMethods;
typedef enum _HevSocks5ProtoCommands HevSocks5ProtoCommands;
typedef enum _HevSocks5ProtoReplies HevSocks5ProtoReplies;
typedef enum _HevSocks5ProtoAddrTypes HevSocks5ProtoAddrTypes;

enum _HevSocks5ProtoMethods
{
	HEV_SOCKS5_PROTO_METHOD_NOAUTH = 0x00,
	HEV_SOCKS5_PROTO_METHOD_GSSAPI = 0x01,
	HEV_SOCKS5_PROTO_METHOD_USERPASS = 0x02,
	HEV_SOCKS5_PROTO_METHOD_NOACCEPTABLE = 0xFF,
};

enum _HevSocks5ProtoCommands
{
	HEV_SOCKS5_PROTO_CMD_CONNECT = 0x01,
	HEV_SOCKS5_PROTO_CMD_BIND = 0x02,
	HEV_SOCKS5_PROTO_CMD_UDP = 0x03,
};

enum _HevSocks5ProtoReplies
{
	HEV_SOCKS5_PROTO_REP_SUCC = 0x00,
	HEV_SOCKS5_PROTO_REP_GENERAL_FAIL = 0x01,
	HEV_SOCKS5_PROTO_REP_NOT_ALLOW = 0x02,
	HEV_SOCKS5_PROTO_REP_NETWORK_UNREACH = 0x03,
	HEV_SOCKS5_PROTO_REP_HOST_UNREACH = 0x04,
	HEV_SOCKS5_PROTO_REP_CONNECT_REFUSED = 0x05,
	HEV_SOCKS5_PROTO_REP_TTL_EXPIRED = 0x06,
	HEV_SOCKS5_PROTO_REP_CMD_NOT_SUPPORT = 0x07,
	HEV_SOCKS5_PROTO_REP_ATYPE_NOT_SUPPORT = 0x08,
};

enum _HevSocks5ProtoAddrTypes
{
	HEV_SOCKS5_PROTO_ATYPE_IPV4 = 0x01,
	HEV_SOCKS5_PROTO_ATYPE_DOMAIN = 0x03,
	HEV_SOCKS5_PROTO_ATYPE_IPV6 = 0x04,
};

int hev_socks5_proto_auth_req_pack (void *buffer, uint8_t method_count,
			uint8_t *methods);
int hev_socks5_proto_auth_req_unpack (void *buffer, uint16_t size,
			uint8_t *method_count, uint8_t **methods);

int hev_socks5_proto_auth_res_pack (void *buffer, uint8_t method);
int hev_socks5_proto_auth_res_unpack (void *buffer, uint16_t size,
			uint8_t *method);

int hev_socks5_proto_req_pack (void *buffer, uint8_t cmd, uint8_t atype,
			const char *addr, uint16_t port);
int hev_socks5_proto_req_unpack (void *buffer, uint16_t size, uint8_t *cmd,
			uint8_t *atype, const char **addr, uint16_t *port);

int hev_socks5_proto_res_pack (void *buffer, uint8_t rep, uint8_t atype,
			const char *addr, uint16_t port);
int hev_socks5_proto_res_unpack (void *buffer, uint16_t size, uint8_t *rep,
			uint8_t *atype, const char **addr, uint16_t *port);

#endif /* __HEV_SOCKS5_PROTO_H__ */

