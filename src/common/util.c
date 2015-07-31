/**
 * File: util.c
 * 
 * Notes: This file contains helper functions used throughout the application.
 * 
 * Authors: Torin Sandall
 *          Stephen Makonin
 * 
 * Date: May/June 2008
 *
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include <netdb.h>

#include "common.h"
#include "util.h"

/**
 * Function: pcap_create
 *
 * Arguments: filter - packet filtering string to apply to the pcap descriptor.
 *
 * Returns: Valid pcap descriptor on success, NULL on failure.
 *
 * Notes: Wraps the pcap descriptor creation process.
 */
pcap_t * pcap_create(const char *filter, const char *dev)
{
    pcap_t *pd = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;

    //if((dev = pcap_lookupdev(errbuf)) == NULL)
    //{
    //    return NULL;
    //}
       
    if((pd = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf)) == NULL)
    {
        return NULL;
    }

    if(pcap_compile(pd, &bpf, filter, 0, 0) < 0)
    {
        return NULL;
    }

    if(pcap_setfilter(pd, &bpf) < 0)
    {
        return NULL;
    }

    return pd;
}

int pcap_create_selectable(const char *filter, const char *dev)
{
	pcap_t *pd = pcap_create(filter, dev);

    if(pd == NULL)
    {
        return -1;
    }

    return pcap_get_selectable_fd(pd);
}

/**
 * Function: ep_add
 *
 * Arguments: epfd - must be a valid epoll descriptor
 *            events - events to signal readiness on
 *            fd - descriptor to add
 *            ptr - data to associate with event
 *
 * Returns: 0 on success, -1 on failure.
 *
 * Notes: This function just wraps the process which adds a new descriptor to an
 * existing epoll descriptor.
 */
int ep_add(int epfd, int events, int fd, void *ptr)
{
    struct epoll_event ev;

    ev.data.ptr = ptr;
    ev.events = events;

    if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        return -1;
    }
		
	return 0;
}

int socket_create_tcp_c32(unsigned long daddr, unsigned short port)
{
    struct sockaddr_in addr;
    int fd = -1;

    //dbg_print("%s: addr=%d, port=%d", __FUNCTION__, addr, port);

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        //dbg_print("%s: socket returned -1, errno=%d", __FUNCTION__, errno);
        goto end_of_func;
    }

    //dbg_print("%s: created socket, fd=%d", __FUNCTION__, fd);

    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = daddr;

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        //dbg_print("%s: connect returned -1, errno=%d", __FUNCTION__, errno);
        goto end_of_func;
    }

end_of_func:
    return fd;
}

int socket_create_tcp_c(const char *host, unsigned short port)
{
    struct sockaddr_in addr;
    int fd = -1;
    struct hostent *ent = NULL;

    //dbg_print("%s: addr=%d, port=%d", __FUNCTION__, addr, port);

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        //dbg_print("%s: socket returned -1, errno=%d", __FUNCTION__, errno);
        goto end_of_func;
    }

    //dbg_print("%s: created socket, fd=%d", __FUNCTION__, fd);

    if((ent = gethostbyname(host)) == NULL)
    {
        //dbg_print("%s: gethostbyname failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        goto end_of_func;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, ent->h_addr, sizeof(addr.sin_addr));

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        //dbg_print("%s: connect returned -1, errno=%d", __FUNCTION__, errno);
        goto end_of_func;
    }

end_of_func:
    return fd;
}

int socket_create_tcp_l(unsigned short port)
{
    struct sockaddr_in addr;
    int ret;

    if((ret = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return -1;
    }

    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    if(bind(ret, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        return -1;
    }

    if(listen(ret, SOMAXCONN) != 0)
    {
        return -1;
    }

    return ret;
}

int socket_create_udp_c(const char *host, unsigned short port)
{
    struct sockaddr_in dest_addr;
    struct hostent *ent;
    int ret;

    if((ret = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return -1;
    }

    if((ent = gethostbyname(host)) == NULL)
    {
        return -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_port = htons(port);
    dest_addr.sin_family = AF_INET;
    memcpy(&dest_addr.sin_addr, ent->h_addr, sizeof(ent->h_addr));

    if(connect(ret, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0)
    {
        return -1;
    }

    return ret;
}

int socket_blk_write(int fd, const void *ptr, ssize_t nb)
{
    int rc = -1;
    ssize_t nsend = 0;
    const char *buf = (const char *)ptr;

    for(;;)
    {
        if((rc = send(fd, buf + nsend, nb - nsend, 0)) < 0)
        {
            goto end_of_func;
        }
        else if(!rc)
        {
            break;
        }
        
        nsend += rc;
    }

end_of_func:
    return rc < 0 ? rc : nsend;
}

int socket_blk_read(int fd, void *ptr, ssize_t *nb)
{
    int rc = -1;
    ssize_t nrecv = 0;
    char *buf = (char *)ptr;

    for(;;)
    {
        if((rc = recv(fd, buf + nrecv, *nb - nrecv, 0)) < 0)
        {
            goto end_of_func;
        }
        else if(!rc)
        {
            break;
        }

        nrecv += rc;
    }

    *nb = nrecv;

end_of_func:
    return rc < 0 ? rc : nrecv;
}


int http_read(int fd, void *ptr, ssize_t *nb)
{
    int rc = -1, header_length = 0, content_length = 0;
    ssize_t nrecv = 0;
    char *buf = (char *)ptr, *token = "Content-Length: ", *cptr;

    memset(ptr, 0, *nb);

    while(1)
    {
        if((rc = recv(fd, buf + nrecv, *nb - nrecv, 0)) < 0)
        {
            goto end_of_func;
        }
        else if(!rc)
        {
            break;
        }

        nrecv += rc;
	
	if(!content_length && strstr(ptr, "\r\n\r\n"))
	{
	    if(!(cptr = strstr(ptr, token)))
	    	break;

	    content_length = strtol(cptr + strlen(token), NULL, 10);
	    header_length = ((unsigned int)strstr(ptr, "\r\n\r\n") - (unsigned int)ptr) + 4;
	}

	if(content_length && nrecv == content_length + header_length)
	    break;
    }

    *nb = nrecv;

end_of_func:
    return rc < 0 ? rc : nrecv;
}

void enc_stream_buffer(const char *keyp _UNUSED, char *buf _UNUSED, size_t len _UNUSED)
{
}

void dec_stream_buffer(const char *key _UNUSED, char *buf _UNUSED, size_t len _UNUSED)
{
}

void timestamp_generate(unsigned long *ts)
{
    srand(time(NULL));
    *ts = rand();
}
