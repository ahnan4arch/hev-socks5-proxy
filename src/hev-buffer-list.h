/*
 ============================================================================
 Name        : hev-buffer-list.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Buffer List
 ============================================================================
 */

#ifndef __HEV_BUFFER_LIST_H__
#define __HEV_BUFFER_LIST_H__

#include <stdint.h>

typedef struct _HevBufferList HevBufferList;

HevBufferList * hev_buffer_list_new (size_t size, size_t max_count);
void hev_buffer_list_destroy (HevBufferList *self);

void * hev_buffer_list_alloc (HevBufferList *self);
void * hev_buffer_list_alloc0 (HevBufferList *self);
void hev_buffer_list_free (HevBufferList *self, void *buffer);
void hev_buffer_list_free_real (HevBufferList *self);

#endif /* __HEV_BUFFER_LIST_H__ */

