/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __QUEUE_H__
#define __QUEUE_H__

typedef struct QUEUE queue;
typedef struct QUEUE_NODE queue_node;

struct QUEUE {
	queue_node *head, *tail;
    unsigned short nelem;
	pthread_mutex_t mutex;
};

struct QUEUE_NODE {
	void *ptr;
	unsigned short len;
	int (*callback)(void *);
	queue_node *next;
};

queue * queue_alloc(void);
int queue_push(queue *, void *, unsigned short, int (*)(void *));
int queue_pop(queue *, void **, unsigned short *, int (**)(void *));

#endif

