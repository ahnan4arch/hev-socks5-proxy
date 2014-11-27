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

typedef struct _HevBufferNode HevBufferNode;

struct _HevBufferList
{
	size_t size;
	size_t free_count;
	void *buffer0;
	HevBufferNode *used_list;
	HevBufferNode *free_list;
};

struct _HevBufferNode
{
	void *buffer;
	HevBufferNode *next;
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

static HevBufferNode *
hev_buffer_nodes_prepend (HevBufferNode *list, HevBufferNode *new)
{
	if (list)
	      new->next = list;
	else
	      new->next = NULL;

	return new;
}

static HevBufferNode *
hev_buffer_nodes_remove (HevBufferNode *list, void *buffer, HevBufferNode **old)
{
	HevBufferNode *node, *prev = NULL;

	if (buffer) {
		for (node=list; node; prev=node,node=node->next) {
			if (buffer == node->buffer) {
				if (prev)
				      prev->next = node->next;
				else
				      list = node->next;
				*old = node;
				break;
			}
		}
	} else {
		*old = list;
		list = list->next;
	}

	return list;
}

static void
hev_buffer_nodes_free (HevBufferNode *list)
{
	HevBufferNode *node = NULL;

	for (node=list; node;) {
		HevBufferNode *curr = node;
		node = node->next;
		hev_free (curr);
	}
}

void
hev_buffer_list_destroy (HevBufferList *self)
{
	HevBufferNode *node;

	if (self->buffer0)
	      hev_free (self->buffer0);

	for (node=self->used_list; node; node=node->next)
	      hev_free (node->buffer);
	hev_buffer_nodes_free (self->used_list);

	for (node=self->free_list; node; node=node->next)
	      hev_free (node->buffer);
	hev_buffer_nodes_free (self->free_list);

	hev_free (self);
}

void *
hev_buffer_list_alloc (HevBufferList *self)
{
	HevBufferNode *node = NULL;

	if (!self->free_list) {
		void *buffer;
		if (0 == self->free_count)
		      return NULL;
		buffer = hev_malloc (self->size);
		if (buffer) {
			node = hev_malloc (sizeof (HevBufferNode));
			if (!node) {
				hev_free (buffer);
				return NULL;
			}
			node->buffer = buffer;
			self->used_list = hev_buffer_nodes_prepend (self->used_list, node);
			self->free_count --;
		}
		return buffer;
	}

	self->free_list = hev_buffer_nodes_remove (self->free_list, NULL, &node);
	self->used_list = hev_buffer_nodes_prepend (self->used_list, node);
	self->free_count --;

	return node->buffer;
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
	HevBufferNode *node = NULL;

	self->used_list = hev_buffer_nodes_remove (self->used_list, buffer, &node);
	self->free_list = hev_buffer_nodes_prepend (self->free_list, node);
	self->free_count ++;
}

void
hev_buffer_list_free_real (HevBufferList *self)
{
	HevBufferNode *node;

	for (node=self->free_list; node; node=node->next)
	      hev_free (node->buffer);
	hev_buffer_nodes_free (self->free_list);
	self->free_list = NULL;
}

