/*
 ============================================================================
 Name        : hev-buffer-list.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Buffer List
 ============================================================================
 */

#include <hev-lib.h>

#include "hev-buffer-list.h"

struct _HevBufferList
{
	size_t size;
	size_t free_count;
	void *buffer0;
	HevSList *used_list;
	HevSList *free_list;
};

HevBufferList *
hev_buffer_list_new (size_t size, size_t max_count)
{
	HevBufferList *self;

	self = hev_malloc0 (sizeof (HevBufferList));
	if (!self)
	      return NULL;

	self->size = size;
	self->free_count = max_count;

	return self;
}

void
hev_buffer_list_destroy (HevBufferList *self)
{
	HevSList *slist;

	if (self->buffer0)
	      hev_free (self->buffer0);

	for (slist=self->used_list; slist; slist=hev_slist_next(slist))
	      hev_free (hev_slist_data (slist));
	hev_slist_free (self->used_list);

	for (slist=self->free_list; slist; slist=hev_slist_next(slist))
	      hev_free (hev_slist_data (slist));
	hev_slist_free (self->free_list);

	hev_free (self);
}

void *
hev_buffer_list_alloc (HevBufferList *self)
{
	void *buffer;

	if (!self->free_list) {
		if (0 == self->free_count)
		      return NULL;
		buffer = hev_malloc (self->size);
		if (buffer) {
			self->used_list = hev_slist_prepend (self->used_list, buffer);
			self->free_count --;
		}
		return buffer;
	}

	buffer = hev_slist_data (self->free_list);
	self->free_list = hev_slist_remove (self->free_list, buffer);
	self->used_list = hev_slist_prepend (self->used_list, buffer);
	self->free_count --;

	return buffer;
}

void *
hev_buffer_list_alloc0 (HevBufferList *self)
{
	if (self->buffer0)
	      return self->buffer0;

	self->buffer0 = hev_malloc0 (self->size);

	return self->buffer0;
}

void
hev_buffer_list_free (HevBufferList *self, void *buffer)
{
	self->used_list = hev_slist_remove (self->used_list, buffer);
	self->free_list = hev_slist_prepend (self->free_list, buffer);
	self->free_count ++;
}

void
hev_buffer_list_free_real (HevBufferList *self)
{
	HevSList *slist;

	for (slist=self->free_list; slist; slist=hev_slist_next(slist))
	      hev_free (hev_slist_data (slist));
	hev_slist_free (self->free_list);
	self->free_list = NULL;
}

