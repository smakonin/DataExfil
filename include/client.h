/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __CLIENT_H__
#define __CLIENT_H__

#define LISTENER   0xFF
#define CLIENT     0x00

extern int send_command_request(const char *, unsigned short, const char *, const char *, unsigned char, const char *);
extern int run_listener(unsigned short, const char *);

#endif

