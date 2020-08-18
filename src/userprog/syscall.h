#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_LIMIT ((void *) 0x8048000)

#include <stdbool.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

typedef int pid_t;

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
void check_address (void *addr);
void get_argument (void *esp, int arg[], int count);

#endif /* userprog/syscall.h */
