#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"

extern struct lock filesys_lock;
int exit_with_status(int status);
void syscall_init (void);

#endif /* userprog/syscall.h */
