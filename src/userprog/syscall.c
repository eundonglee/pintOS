#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

/* Power off pintos. */
void halt (void)
{
  shutdown_power_off();
}

/* Print exit message and exit process. */
void exit (int status)
{
  struct thread *t = thread_current ();

  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, t->exit_status);
  thread_exit();
}

/* Create a child thread and return thread ID of it. */
pid_t exec (const char *cmd_line)
{
  pid_t cpid; /* ID of a child preocess */
  struct thread *cp;

  cpid = process_execute (cmd_line);
  cp = get_child_process (cpid);

  sema_down(& cp->sema_load);

  /* If the child process load failed, return -1. */
  if (cp->load_done == false)
    return -1;

  return cpid;
}

/* Wait until the child process exits */
int wait (tid_t tid)
{ 
  int status = process_wait(tid);
  return status;
}

/* Create file and return the result. */
bool create (const char *file, unsigned initial_size)
{
  bool success = filesys_create (file, initial_size);
  return success;
}

/* Remove file and return the result. */
bool remove (const char *file)
{
  bool success = filesys_remove (file);
  return success;
}

/* Open file and return file descriptor index. */
int open (const char *file)
{  
  struct file *f;
  lock_acquire (& filesys_lock);

  f = filesys_open (file);  
  if (f != NULL)
  {
    lock_release (& filesys_lock);
    return process_add_file (f); 
  }
  else
  {
    lock_release (& filesys_lock);
    return -1;
  }
}

/* Return file size. */
int filesize (int fd)
{
  struct file *f = process_get_file (fd);

  if (f != NULL)
    return file_length (f);
  else
    return -1;
}

/* Read data from file into buffer. */
int read (int fd, void *buffer, unsigned size)
{
  struct file *f = process_get_file (fd);
  uint8_t *bf_ptr;
  int actual_size;

  lock_acquire (& filesys_lock);

  if (fd == 0)
  {
    for (actual_size = 0; (unsigned) actual_size < size; actual_size++)
    {
      bf_ptr = buffer + actual_size;
      *bf_ptr = input_getc ();
      if (! *bf_ptr)
        break;
    } 
  }

  else if (f != NULL) 
    actual_size = file_read (f, buffer, size);

  else
  {
    lock_release (& filesys_lock);
    return -1;
  }

  lock_release (& filesys_lock);
  return actual_size;
}

/* Write data from buffer into file. */
int write (int fd, void *buffer, unsigned size)
{
  struct file *f = process_get_file (fd);
  int actual_size;

  lock_acquire (& filesys_lock);

  if (fd == 1)
  {
    putbuf (buffer, size);
    actual_size = size;
  }

  else if (f != NULL) 
    actual_size = file_write (f, buffer, size);

  else
  {
    lock_release (& filesys_lock);
    return -1;
  }

  lock_release (& filesys_lock);
  return actual_size;
}

/* Move offset of the file. */
void seek (int fd, unsigned position)
{
  struct file *f = process_get_file (fd);

  file_seek (f, position);
}

/* Return current offset of the file. */
unsigned tell (int fd)
{
  struct file *f = process_get_file (fd);
  unsigned pos;

  pos = file_tell (f);
  return pos; 
}

/* Close the file. */
void close (int fd)
{
  process_close_file (fd);
}

/* Check whether the address is in user space. If the address is outside user space, exit the thread */
void check_address (void *addr)
{
  if (addr < USER_LIMIT || PHYS_BASE <= addr)
  {
    exit(-1);
  }
}

/* Take arguments from stack */
void get_argument (void *esp, int arg[], int count)
{
  int *sp = esp;

  int i;
  for (i = 0; i < count; i++)
  {
    sp = sp + 1;
    arg[i] = *sp;
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init (& filesys_lock);  
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *ptr = f -> esp;

  check_address ((void *)ptr);
  int syscall_number = *ptr;
  int arg[10];

  //printf("syscall_number : %d\n", syscall_number);
  //hex_dump ((uintptr_t) ptr, ptr, 24, true);   

  switch (syscall_number)
  {
    case SYS_HALT:
      halt ();
      break;

    case SYS_EXIT:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      exit (arg[0]);
      break; 

    case SYS_EXEC:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      check_address ((void *) arg[0]);
      f -> eax = exec ((char *) arg[0]);
      break;

    case SYS_WAIT:     
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      f -> eax = wait ((tid_t) arg[0]);
      break;

    case SYS_CREATE:
      check_address ((void *) (ptr + 2));
      get_argument (ptr, arg, 2);
      check_address ((void *) arg[0]);
      f -> eax = create ((char *) arg[0], (unsigned) arg[1]);
      break;

    case SYS_REMOVE:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      check_address ((void *) arg[0]);
      f -> eax = remove ((char *) arg[0]);
      break;

    case SYS_OPEN:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      check_address ((void *) arg[0]);
      f -> eax = open ((char *) arg[0]);
      break;

    case SYS_FILESIZE:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      f -> eax = filesize (arg[0]);
      break;

    case SYS_READ:
      check_address ((void *) (ptr + 3));
      get_argument (ptr, arg, 3);
      check_address ((void *) arg[1]);
      f -> eax = read (arg[0], (void *)arg[1], (unsigned)arg[2]);
      break;

    case SYS_WRITE:
      check_address ((void *) (ptr + 3));
      get_argument (ptr, arg, 3);
      check_address ((void *) arg[1]);
      f -> eax = write (arg[0], (void *)arg[1], (unsigned)arg[2]);
      break;

    case SYS_SEEK:
      check_address ((void *) (ptr + 2));
      get_argument (ptr, arg, 2);
      seek (arg[0], (unsigned) arg[1]);
      break;

    case SYS_TELL:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      f -> eax = tell (arg[0]);
      break;

    case SYS_CLOSE:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      close (arg[0]);
      break;

    default:
      thread_exit();
      break;
  }
}
