/**
 * File: google.c
 * 
 * Notes: This file contains google http spoof functions.
 * 
 * Authors: Stephen Makonin
 *          Torin Sandall
 * 
 * Date: May/June 2008
 *
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include "common.h"

void dbg_print(const char *fmt, ...)
{
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
#endif
}
