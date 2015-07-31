/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */
     
#ifndef __UTIL_H__
#define __UTIL_H__

#include <pcap.h>
#include <sys/epoll.h>

#define MAX(a,b) (a) > (b) ? (a) : (b)

extern void dbg_print(const char *, ...);
extern void timestamp_generate(unsigned long *);
extern int ep_create(unsigned int, struct epoll_event **);
extern int ep_add(int, int, int, void *);
extern pcap_t * pcap_create(const char *, const char *);
extern int pcap_create_selectable(const char *, const char *);
extern void enc_stream_buffer(const char *, char *, size_t);
extern void dec_stream_buffer(const char *, char *, size_t);
extern int socket_create_udp_c(const char *, unsigned short);
extern int socket_create_tcp_l(unsigned short);
extern int socket_create_tcp_c(const char *, unsigned short);
extern int socket_create_tcp_c32(unsigned long, unsigned short);
extern int socket_blk_write(int, const void *, ssize_t);
extern int socket_blk_read(int, void *, ssize_t *);
extern int http_read(int, void *, ssize_t *);

#endif

