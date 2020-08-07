#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
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
  char *tn = thread_current () -> name;
  printf ("%s: exit(%d)", tn, status);
  thread_exit();
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

/* Check whether the address in user space. If the address is outside user space, exit the thread */
void check_address (void *addr)
{
  if (addr < USER_LIMIT || PHYS_BASE < addr)
  {
    exit(-1);
  }
}

/* Take arguments from stack */
void get_argument (void *esp, char **arg, int count)
{
  char *sp = esp;

  int i;
  for (i = 0; i < count; i++)
  {
    sp = sp + strlen(sp);
    while (*sp == '\0')
    {
      sp = sp + 1;
    }
    arg[i] = sp;
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  int *ptr = f -> esp;

  check_address ((void *)ptr);
  int syscall_number = *ptr;
  char **arg;

  switch (syscall_number)
  {
    case SYS_HALT:
      halt ();
      break;

    case SYS_EXIT:
      exit (0);
      break; 

    case SYS_CREATE:
      arg = malloc(2);
      get_argument(ptr, arg, 2);
      check_address ((void *)arg[0]);
      check_address ((void *)arg[1]);
      create(arg[0], (unsigned) atoi(arg[1]));
      free(arg);
      break;

    case SYS_REMOVE:
      arg = malloc(1);
      get_argument(ptr, arg, 1);
      check_address ((void *)arg[0]);
      remove(arg[0]);
      free(arg);
      break;

    default:
      hex_dump((uintptr_t)(*f).esp, (*f).esp, PHYS_BASE - (*f).esp, true);
      thread_exit();
      break;
  }
}
