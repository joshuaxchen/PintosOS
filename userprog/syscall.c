#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;

#define NUM_CHARS_IN_CONSOLE_WRITE 65536

// Driver start: Ankit
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}
// Driver end: Ankit

// Driver start: Jimmy
int exit_with_status(int status) {
  struct process_info *pi = &thread_current()->process_info;
  pi->exit_status = status;
  int i;
  for (i = 0; i < 16; i++) {
    if (thread_current()->name[i] == ' ') {
      thread_current()->name[i] = 0;
      break;
    }
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);

  for (i = 0; i < 128; i++) {
    if (pi->files[i]) {
	    lock_acquire(&filesys_lock);
	    file_close(pi->files[i]);
	    lock_release(&filesys_lock);
      pi->files[i] = NULL;
	  }
  }
  if (!list_empty(&pi->children)) {
    struct list_elem *child_elem;
    for (child_elem = list_begin(&pi->children); child_elem != list_end(&pi->children); child_elem = list_next(child_elem)) {
      struct process_info *child = list_entry(child_elem, struct process_info, elem);
      sema_up(&child->exit_semaphore);
    }
  }
  sema_up(&pi->wait_semaphore);
  sema_down(&pi->exit_semaphore);
  thread_exit();
  return -1;
}
// Driver end: Jimmy

// Driver start: Joshua, Ankit
static int is_valid_addr(void *addr, bool write, char *esp) {
  (void)write;
  (void)esp;
  if (addr == NULL)
    return false;
  if (!is_user_vaddr(addr))
    return false;
  return pagedir_get_page(thread_current()->pagedir, addr) != NULL;
}

static void check_addr(void *addr, size_t len, bool write, char *esp) {
  size_t offset;
  for (offset = 0; offset < len; offset += PGSIZE)
    if (!is_valid_addr((char*)addr + offset, write, esp - sizeof(uint32_t)))
      exit_with_status(-1);
  if (!is_valid_addr((char*)addr + len - 1, write, esp - sizeof(uint32_t)))
    exit_with_status(-1);
}

static void check_str_addr(char *addr, bool write, char *esp) {
  size_t offset = 0;
  while (true) {
    if (!is_valid_addr(addr + offset, write, esp - sizeof(uint32_t)))
      exit_with_status(-1);
    if (addr[offset] == 0)
      return;
    offset++;
  }
}

static int sys_halt(void) {
  shutdown_power_off();
  return -1;
}

static int sys_exit(char *params) {
  check_addr(params, sizeof(int), false, params);
  int status = *(int*)params;

  return exit_with_status(status);
}
// Driver end: Joshua, Ankit

// Driver start: Ankit
static int sys_exec(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *cmd_line = *(char**)params;
  check_str_addr(cmd_line, false, params);

  tid_t tid = process_execute(cmd_line);
  struct process_info *pi = &thread_current()->process_info;
  struct process_info *child = list_entry(list_rbegin(&pi->children), struct process_info, elem);
  sema_down(&child->exec_semaphore);
  if (child->exec_status == -1) {
    list_pop_back(&pi->children);
    sema_up(&child->exit_semaphore);
    return -1;
  }
  return tid;
}
// Driver end: Ankit

// Driver start: Jimmy
static int sys_wait(char *params) {
  check_addr(params, sizeof(pid_t), false, params);
  pid_t pid = *(pid_t*)params;

  return process_wait(pid);
}

static int sys_create(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *file = *(char**)params;
  check_str_addr(file, false, params);
  params += sizeof(char*);
  check_addr(params, sizeof(unsigned), false, params);
  unsigned initial_size = *(unsigned*)params;

  lock_acquire(&filesys_lock);
  int result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;
}
// Driver end: Jimmy

// Driver start: Ankit
static int sys_remove(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *file = *(char**)params;
  check_str_addr(file, false, params);

  lock_acquire(&filesys_lock);
  int result = filesys_remove(file);
  lock_release(&filesys_lock);

  return result;
}

static int sys_open(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *file = *(char**)params;
  check_str_addr(file, false, params);

  struct process_info *pi = &thread_current()->process_info;
  int i;
  for (i = 3; i < 128; i++) {
    if (!pi->files[i])
      break;
  }
  if (i >= 128)
    return -1;
  lock_acquire(&filesys_lock);
  struct file *file_obj = filesys_open(file);
  lock_release(&filesys_lock);
  if (!file_obj)
	return -1;
  pi->files[i] = file_obj;
  return i;
}
// Driver end: Ankit

// Driver start: Joshua
static int sys_filesize(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  lock_acquire(&filesys_lock);
  int result = file_length(file);
  lock_release(&filesys_lock);
  return result;
}
// Driver end: Joshua

// Driver start: Ankit, Jimmy
static int sys_read(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd >= 128)
    return -1;
  params += sizeof(int);
  check_addr(params, sizeof(void*), false, params);
  void *buffer = *(void**)params;
  params += sizeof(void*);
  check_addr(params, sizeof(unsigned), false, params);
  unsigned size = *(unsigned*)params;
  check_addr(buffer, size, true, params);

  if (fd == 0) {
    unsigned i;
    for (i = 0; i < size; i++)
      ((char*)buffer)[i] = input_getc();
    return size;
  } else if (fd < 3) {
    return -1;
  }
  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  if (inode_isdir(file_get_inode(file)))
    return -1;
  lock_acquire(&filesys_lock);
  int result = file_read(file, buffer, size);
  lock_release(&filesys_lock);
  return result;
}
// Driver end: Ankit, Jimmy

// Driver start: Joshua, Jimmy
static int sys_write(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd >= 128)
    return -1;
  params += sizeof(int);
  check_addr(params, sizeof(void*), false, params);
  void *buffer = *(void**)params;
  params += sizeof(void*);
  check_addr(params, sizeof(unsigned), false, params);
  unsigned size = *(unsigned*)params;
  check_addr(buffer, size, false, params);

  if (fd == 1) {
    unsigned i;
    for (i = 0; i < size; i += NUM_CHARS_IN_CONSOLE_WRITE)
      if (size - i < NUM_CHARS_IN_CONSOLE_WRITE)
        putbuf((char*)buffer + i, size - i);
      else
        putbuf((char*)buffer + i, NUM_CHARS_IN_CONSOLE_WRITE);
    return size;
  } else if (fd < 3) {
    return -1;
  }
  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  if (inode_isdir(file_get_inode(file)))
    return -1;
  lock_acquire(&filesys_lock);
  int result = file_write(file, buffer, size);
  lock_release(&filesys_lock);
  return result;
}
// Driver end: Joshua, Jimmy

// Driver start: Jimmy
static int sys_seek(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;
  params += sizeof(int);
  check_addr(params, sizeof(unsigned), false, params);
  unsigned position = *(unsigned*)params;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  if (inode_isdir(file_get_inode(file)))
    return -1;
  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
  return 0;
}
// Driver end: Jimmy

// Driver start: Ankit
static int sys_tell(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  if (inode_isdir(file_get_inode(file)))
    return -1;
  lock_acquire(&filesys_lock);
  int result = file_tell(file);
  lock_release(&filesys_lock);
  return result;
}
// Driver end: Ankit

// Driver start: Joshua
static int sys_close(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  if (!file)
    return -1;
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
  pi->files[fd] = NULL;
  return 0;
}
// Driver end: Joshua

static int sys_chdir(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *dir = *(char**)params;
  check_str_addr(dir, false, params);

  if (!filesys_chdir(dir))
    return false;
  return true;
}

static int sys_mkdir(char *params) {
  check_addr(params, sizeof(char*), false, params);
  char *dir = *(char**)params;
  check_str_addr(dir, false, params);

  if (!filesys_mkdir(dir))
    return false;
  return true;
}

static int sys_readdir(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;
  params += sizeof(int);
  check_addr(params, sizeof(char*), false, params);
  char *name = *(char**)params;
  check_addr(name, NAME_MAX + 1, false, params);

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  struct dir *dir = dir_open(file_get_inode(file));
  dir_setpos(dir, file_tell(file));
  bool success = dir_readdir(dir, name);
  if (success) {
	  file_seek(file, dir_getpos(dir));
	  // printf("read dir as %s for fd %d success %d\n", name, fd, success);
  }
  return success;
}

static int sys_isdir(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  return inode_isdir(file_get_inode(file));
}

static int sys_inumber(char *params) {
  check_addr(params, sizeof(int), false, params);
  int fd = *(int*)params;
  if (fd < 3 || fd >= 128)
    return -1;

  struct process_info *pi = &thread_current()->process_info;
  struct file *file = pi->files[fd];
  return inode_get_inumber(file_get_inode(file));
}

// Driver start: Jimmy
static void
syscall_handler (struct intr_frame *f) 
{
  char *esp = f->esp;
  check_addr(esp, sizeof(uint32_t), false, esp + sizeof(uint32_t));
  int call_num = *(uint32_t*)esp;
  esp += sizeof(uint32_t);

  // switch statement for all sys calls
  switch(call_num) {
  case SYS_HALT:
    f->eax = sys_halt();
    break;
  case SYS_EXIT:
    f->eax = sys_exit(esp);
    break;
  case SYS_EXEC:
    f->eax = sys_exec(esp);
    break;
  case SYS_WAIT:
    f->eax = sys_wait(esp);
    break;
  case SYS_CREATE:
    f->eax = sys_create(esp);
    break;
  case SYS_REMOVE:
    f->eax = sys_remove(esp);
    break;
  case SYS_OPEN:
    f->eax = sys_open(esp);
    break;
  case SYS_FILESIZE:
    f->eax = sys_filesize(esp);
    break;
  case SYS_READ:
    f->eax = sys_read(esp);
    break;
  case SYS_WRITE:
    f->eax = sys_write(esp);
    break;
  case SYS_SEEK:
    f->eax = sys_seek(esp);
    break;
  case SYS_TELL:
    f->eax = sys_tell(esp);
    break;
  case SYS_CLOSE:
    f->eax = sys_close(esp);
    break;
  case SYS_CHDIR:
    f->eax = sys_chdir(esp);
    break;
  case SYS_MKDIR:
    f->eax = sys_mkdir(esp);
    break;
  case SYS_READDIR:
    f->eax = sys_readdir(esp);
    break;
  case SYS_ISDIR:
    f->eax = sys_isdir(esp);
    break;
  case SYS_INUMBER:
    f->eax = sys_inumber(esp);
    break;
  default:
    thread_exit();
  }
}
// Driver end: Jimmy
