/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include "common.h"
#include "queue.h"

static queue_node * queue_node_alloc(void)
{
	queue_node *ret;
	
	if((ret = (queue_node *)malloc(sizeof(queue_node))) == NULL)
		return NULL;
		
	ret->ptr = NULL;
	ret->len = 0;
	ret->callback = NULL;
	ret->next = NULL;
	
	return ret;
}

queue * queue_alloc()
{
	queue *ret;
	
	if((ret = (queue *)calloc(1, sizeof(queue))) == NULL)
		return NULL;

	if((ret->head = queue_node_alloc()) == NULL) {
		free(ret);
		return NULL;
	}
	
	ret->tail = ret->head;
    ret->nelem = 0;
	
	return ret;	
}

int queue_push(queue *Q, void *ptr, unsigned short len, int (*cb)(void *))
{
	int ret = SUCCESS;

	pthread_mutex_lock(&Q->mutex);

	if(Q->head == NULL)
	{
		if((Q->head = queue_node_alloc()) == NULL)
		{
			fprintf(stderr, "MALLOC OR SOMETHING FAILED, GET THE FUCK OUT\n");
			exit(1);		
		}
	}

	if(Q->head->ptr == NULL)
	{
		Q->head->ptr = ptr;
		Q->head->len = len;
		Q->head->callback = cb;
	}
	else 
	{
		if((Q->tail->next = queue_node_alloc()) == NULL) 
		{
			ret = FAIL;
			goto done;
		}
		
		Q->tail->next->ptr = ptr;
		Q->tail->next->len = len;
		Q->tail->next->callback = cb;
		Q->tail = Q->tail->next;
	}

    Q->nelem++;

done:
	pthread_mutex_unlock(&Q->mutex);
	return ret;
}

int queue_pop(queue *Q, void **ptr, unsigned short *len, int (**cb)(void *))
{
	int ret = SUCCESS;
    queue_node *bk;

	pthread_mutex_lock(&Q->mutex);

	if(Q->head->ptr == NULL) {
		ret = FAIL;
		goto done;
	}
		
	*ptr = Q->head->ptr;
	*len = Q->head->len;
	*cb = Q->head->callback;
	bk = Q->head;
	Q->head = Q->head->next;
        Q->nelem--;
    free(bk);
	
done:
	pthread_mutex_unlock(&Q->mutex);
	return ret;	
}

