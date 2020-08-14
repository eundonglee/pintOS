#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_LIMIT ((void *) 0x8048000)

#include <stdbool.h>
#include "threads/thread.h"

typedef int pid_t;

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (tid_t tid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
void check_address (void *addr);
void get_argument (void *esp, char **arg, int count);

#endif /* userprog/syscall.h */
