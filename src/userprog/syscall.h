#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_LIMIT ((void *) 0x8048000)

#include <stdbool.h>

void syscall_init (void);
void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
void check_address (void *addr);
void get_argument (void *esp, char **arg, int count);

#endif /* userprog/syscall.h */
