#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/page.h"

int token_count (char *string);
tid_t process_execute (const char *file_name);
void argument_stack (char *parse[], int count, void **esp);
struct thread *get_child_process (int pid); 
void remove_child_process (struct thread *cp);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool verify_stack (void *esp, void *sp);
bool expand_stack (void *addr);
int process_add_file (struct file *f);
struct file *process_get_file (int fd);
void process_close_file (int fd);
void do_munmap (struct mmap_file *mmf);
bool handle_mm_fault (struct vm_entry *vme);

#endif /* userprog/process.h */
