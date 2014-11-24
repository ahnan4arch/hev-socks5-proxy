/*
 ============================================================================
 Name        : hev-buffer.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Buffer
 ============================================================================
 */

#ifndef __HEV_BUFFER_H__
#define __HEV_BUFFER_H__

#include <stdint.h>

#define HEV_BUFFER_DATA_SIZE	(4096-4)

typedef struct _HevBuffer HevBuffer;

struct _HevBuffer
{
	uint16_t offset;
	uint16_t length;
	uint8_t data[HEV_BUFFER_DATA_SIZE];
};

#endif /* __HEV_BUFFER_H__ */

