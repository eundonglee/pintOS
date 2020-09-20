#include "userprog/syscall.h"
#include <debug.h>
#include <list.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "vm/page.h"
#include "vm/frame.h"

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

  //debug_backtrace ();
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

  lock_release (& filesys_lock);

  if (f != NULL)
    return process_add_file (f); 
  else
    return -1;
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

  //printf ("read f: 0x%x t: 0x%x, h: 0x%x\n", f, thread_current(), filesys_lock.holder);
  lock_acquire (& filesys_lock);
  //printf ("read lock aquired f: 0x%x t: 0x%x, h: 0x%x\n", f, thread_current(), filesys_lock.holder);

  pin_address (buffer, size);
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
  //printf ("read lock release f: 0x%x t: 0x%x, h: 0x%x\n", f, thread_current(), filesys_lock.holder);
  unpin_address (buffer, size);
  lock_release (& filesys_lock);
  return actual_size;
}

/* Write data from buffer into file. */
int write (int fd, void *buffer, unsigned size)
{
  struct file *f = process_get_file (fd);
  int actual_size;

  lock_acquire (& filesys_lock);

  pin_address (buffer, size);
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
	unpin_address (buffer, size);
    return -1;
  }

  unpin_address (buffer, size);
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

/* Map file to virtual memory address area. */
int mmap (int fd, void *addr)
{
  struct file *f = process_get_file (fd);
  int size = filesize (fd);
  void *ptr;

  if (f == NULL) return -1;
  if (addr == NULL ) return -1;
  if (pg_ofs (addr) != 0) return -1;
  for (ptr = addr; ptr < addr+size; ptr += PGSIZE)
	if (find_vme (ptr)) return -1;

  struct thread *cur = thread_current ();
  struct file *new_f = file_reopen (f);
  int mapid = cur->mapid_next++;
  struct mmap_file *mmf = malloc (sizeof (struct mmap_file));
  struct vm_entry *vme;

  mmf->mapid = mapid;
  mmf->file = new_f;
  list_push_back (& cur->mmap_list, & mmf->elem);
  list_init (& mmf->vme_list);

  int ofs = 0;
  while (size > 0)
  {
	vme = malloc (sizeof (struct vm_entry));
	vme->vaddr = addr;
	vme->type = VM_FILE;
	vme->is_loaded = false;
	vme->pinned = false;
	vme->writable = true;
	vme->file = new_f;
	vme->offset = ofs;
	vme->read_bytes = size < PGSIZE? size: PGSIZE;
	vme->zero_bytes = size < PGSIZE? PGSIZE-size : 0;
	list_push_back (& mmf->vme_list, & vme->mmap_elem);
	insert_vme (& thread_current ()->vm, vme);

	addr += PGSIZE;
	ofs += PGSIZE;
	size -= PGSIZE;
  }

  //printf ("mapid : %d vme : %p vaddr : %p\n", mapid, vme, vme->vaddr);
  return mapid;
}

/* Unmap the file from virtual address and remove the vm entry which corresponds to the mapping. */
void munmap (int mapping)
{
  struct list *mmap_list = & thread_current ()->mmap_list;
  struct mmap_file *mmf;

  struct list_elem *e = list_begin (mmap_list);
  while (e != list_end (mmap_list))
  {
	mmf = list_entry (e, struct mmap_file, elem);
	//printf ("e : 0x%x mmf : 0x%x mapping : %d\n", e, mmf, mapping);
	if (mmf->mapid == mapping) 
	{
	  e = list_remove (e);
	  do_munmap (mmf);
	  break;
	}
	else e = list_next (e);
  }
}


/* Check whether the address is in user space. If the address is outside user space, exit the thread */
void check_address (void *addr)
{
  if (addr < USER_LIMIT || PHYS_BASE <= addr)
    exit(-1);
}

/* Find vm_entry which corresponds to the address corresponds. If it exists, return it. */
/*struct vm_entry *check_vaddr (void *vaddr)
{
  struct vm_entry *vme = find_vme (vaddr);
  if (vme == NULL)
	exit (-1);
  return vme;
}
*/

/* Check whether the buffer area is covered by vm entries. If not, exit the thread. */
void check_valid_buffer (void *buffer, unsigned size, bool to_write)
{
  struct vm_entry *vme;
  void *ptr = buffer;

  check_address (buffer);
 
  for (;ptr < pg_round_up (buffer+size); ptr += PGSIZE)
  {
	vme = find_vme (ptr);
	if (vme == NULL) 
	  exit(-1);
	if (to_write == true && vme->writable == false) 
	  exit (-1);
  }
}

/* Check whether any m_entry which corresponds to the address of the string. */
void check_valid_string (void *str)
{
  struct vm_entry *vme;

  check_address (str);
 
  vme = find_vme (str);
  //printf ("string : %s, vme : 0x%x\n", str, vme); 
  if (vme == NULL) 
	exit(-1);
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
  //hex_dump ((uintptr_t) ptr, ptr, 96, true);   

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
      check_valid_string ((void *) arg[0]);
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
      check_valid_string ((void *) arg[0]);
      f -> eax = create ((char *) arg[0], (unsigned) arg[1]);
      break;

    case SYS_REMOVE:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      check_valid_string ((void *) arg[0]);
      f -> eax = remove ((char *) arg[0]);
      break;

    case SYS_OPEN:
      check_address ((void *) (ptr + 1));
      get_argument (ptr, arg, 1);
      check_valid_string ((void *) arg[0]);
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
	  check_valid_buffer ((void *)arg[1], (unsigned)arg[2], true);
      f -> eax = read (arg[0], (void *)arg[1], (unsigned)arg[2]);
      break;

    case SYS_WRITE:
      check_address ((void *) (ptr + 3));
      get_argument (ptr, arg, 3);
	  check_valid_buffer ((void *) arg[1], (unsigned)arg[2], false);
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

	case SYS_MMAP:
	  check_address ((void *) (ptr + 2));
	  get_argument (ptr, arg, 2);
	  f -> eax = mmap (arg[0], (void *) arg[1]);
	  break;

	case SYS_MUNMAP:
	  check_address ((void *) (ptr + 1));
	  get_argument (ptr, arg, 1);
	  munmap (arg [0]);
	  break;

    default:
      thread_exit();
      break;
  }
}
