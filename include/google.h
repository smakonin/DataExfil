/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __GOOGLE_H__
#define __GOOGLE_H__

#include <openssl/rc4.h>
#include<stddef.h>
#include<stdio.h>
#include<sys/types.h>
#include<dirent.h>
#include<sys/stat.h>
#include<regex.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>

#define MAX_PHRASE_LEN 63

typedef unsigned char uchar;
typedef struct GOOGLE_SESSION google_session;

struct GOOGLE_SESSION
{
    char search_phrase[MAX_PHRASE_LEN + 1];
    int page_no;
};

extern const char *http_initial_get_request;

extern void g_start_search_session(google_session *);
extern void g_create_search_request(google_session *, char *, int, char *);
extern int g_get_request_payload(char *, char *);

#endif
