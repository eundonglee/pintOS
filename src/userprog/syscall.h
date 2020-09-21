#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_LIMIT ((void *) 0x08048000)

#include <stdbool.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

typedef int pid_t;

/* Lock to prevent another thread from writing on file while file being read. */
struct lock filesys_lock;

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (tid_t tid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int mmap (int fd, void *addr);
void munmap (int mapping);
void check_address (void *addr);
struct vm_entry *check_vaddr (void *vaddr);
void check_valid_buffer (void *esp, void *buffer, unsigned size, bool to_write);
void check_valid_string (void *str);
void get_argument (void *esp, int arg[], int count);

#endif /* userprog/syscall.h */
