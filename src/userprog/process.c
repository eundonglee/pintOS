#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Count how many tokens are in string. */
int token_count (char *string)
{
  int string_length = strlen (string);
  char str_copy [string_length + 1];
  char *save_ptr; 
  char *token;
  int count;

  strlcpy (str_copy, string, string_length + 1);
  token = strtok_r (str_copy, " ", &save_ptr);
  count = 0;
  while (token)
  {
    count++;
    token = strtok_r (NULL, " ", &save_ptr);
  }

  return count;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *thread_name;
  char *save_ptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  thread_name = palloc_get_page (0);
  if (fn_copy == NULL)
  {
    if (thread_name) palloc_free_page (thread_name);
    return TID_ERROR;
  }
  if (thread_name == NULL)
  {
    if (fn_copy) palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (thread_name, file_name, PGSIZE);
  /* Parse a string before the first whitespace. */
  thread_name = strtok_r (thread_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) palloc_free_page (fn_copy);
  if (thread_name) palloc_free_page (thread_name);
   
  return tid;
}

void argument_stack (char *parse[], int count, void **esp)
{
  char *argv[count];
  int i, j, k;
  int argLength;
  int totalArgLength;

  /* Push arguments into stack and save address in which arguments are pushed. */
  totalArgLength = 0;
  for (i = count - 1 ; i > -1 ; i--)
  { 
    argLength = strlen(parse[i]);
    for (j = argLength ; j > -1 ; j--)
    {
      *esp = *esp - 1;
      totalArgLength = totalArgLength + 1;
      ** (char **)esp = parse[i][j];
    }
    argv[i] = *esp;
  }
  *esp = *esp - ((4 - totalArgLength % 4) ? totalArgLength % 4 != 0 : 0);

  /* Push argv in stack. */
  *esp = *esp - 4;
  ** (char ***)esp = 0;
  for (k = count - 1 ; k > -1 ; k--)
  {
    *esp = *esp - 4;
    ** (char ***)esp = argv[k];
  }
  *esp = *esp - 4;
  ** (char ****)esp = *esp + 4;
  
  /* Push argc. */
  *esp = *esp - 4;
  ** (int **)esp = count;

  /* Push return address */
  *esp = *esp - 4;
  ** (void ***)esp = 0;
}

/* Return a child process descriptor */
struct thread *get_child_process (int pid)
{
  struct thread *pt;     /* Parent thread */
  struct thread *ct;     /* Child thread */
  struct list *cl;        /* Child thread list */
  struct list_elem *e;   /* An element of child thread list */

  pt = thread_current ();
  cl = &pt->child_list;

  for (e = list_begin (cl); e != list_end (cl); e = list_next (e))
  { 
    ct = list_entry (e, struct thread, child_list_elem);
    if (ct->tid == pid)
      return ct;
  }

  return NULL;
}

/* Delete and free a child process */
void remove_child_process (struct thread *cp)
{
  list_remove (& cp -> child_list_elem);
  palloc_free_page (cp); 
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  int file_name_length = strlen(file_name);
  char fn_copy[file_name_length+1];
  bool success;
  char *token;
  char *save_ptr;
  int arg_count = token_count (file_name);
  char *parse[arg_count];
  struct intr_frame if_;
  struct thread *cp = thread_current ();  

  /* Tokenize FILE_NAME. */
  strlcpy(fn_copy, file_name, file_name_length+1);

  token = strtok_r(fn_copy, " ", &save_ptr);

  int i = 0;
  while (token)
  { 
    parse[i] = token;
    i++;
    token = strtok_r(NULL, " ", &save_ptr);
  }

  /* Initialize the virtual memory hash table of the child thread. */
  vm_init (& cp->vm);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (parse[0], &if_.eip, &if_.esp);

  /* When child process load finished, continue parent process. */
  cp -> load_done = success;
  sema_up (& cp->sema_load);

  palloc_free_page (file_name);
  /* If load failed, quit. */
  if (!success) 
    thread_exit ();
  /* Save arguments on stack. */
  else
    argument_stack(parse, arg_count, &if_.esp);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *ct;
  int exit_status;

  ct = get_child_process (child_tid);

  /* When child_tid not found in child_list, return -1. */
  if (ct == NULL)
    return -1;

  sema_down (& ct->sema_exit);

  exit_status = ct->exit_status;
  remove_child_process (ct);

  return exit_status;  
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct mmap_file *mmf;
  uint32_t *pd;
  int fd;

  for (fd = (cur->fd_next) - 1 ; fd >= 2 ; fd--)
    process_close_file (fd);
  
  free (cur->fd_table);

  file_close (cur->run_file);

  struct list_elem *e = list_begin (& cur->mmap_list);
  while (e != list_end (& cur->mmap_list))
  {
	mmf = list_entry (e, struct mmap_file, elem);
	e = list_remove (e);
	do_munmap (mmf);
  }

  vm_destroy (& cur->vm);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
	  //printf ("thread : %s\n", cur->name);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  lock_acquire (& filesys_lock);
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release (& filesys_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  t->run_file = file;
  file_deny_write (file);  
  lock_release (& filesys_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  /* Do not close file until porcess exit */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
/*      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;
*/
      /* Load this page. */
/*      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
*/
      /* Add the page to the process's address space. */
/*      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
*/

	  /* Set the member values in vm_entry and insert it into vm hash table. */
	  struct vm_entry *vme = malloc (sizeof (struct vm_entry));
	  vme->type = VM_BIN;
	  vme->vaddr = (void *) upage;
	  vme->writable = writable;
	  vme->is_loaded = false;
	  vme->pinned = false;
	  vme->file = file;
	  vme->offset = ofs;
	  vme->read_bytes = page_read_bytes;
	  vme->zero_bytes = page_zero_bytes;
	  insert_vme (& thread_current ()->vm, vme);
	  //printf ("vme : 0x%x, vaddr : 0x%x, file : 0x%x, writable : %d\n", vme, vme->vaddr, file, vme->writable);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
	  ofs += page_read_bytes;
	  upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  //uint8_t *kpage;
  struct page *page;
  bool success = false;
  struct vm_entry *vme;
  
  /* kpage = palloc_get_page (PAL_USER | PAL_ZERO); */

  /*
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  */

  page = alloc_page (PAL_USER | PAL_ZERO);

  success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, page->kaddr, true);
  if (!success)
  {
	free_page (page->kaddr);
	return success;
  }

  *esp = PHYS_BASE;

  /* Initailize the vm_entry and insert it into the vm hash table. */
  vme = malloc (sizeof (struct vm_entry));
  page->vme = vme;
  vme->type = VM_ANON;
  vme->vaddr = (void *) (((uint8_t *) PHYS_BASE) - PGSIZE);
  vme->writable = true;
  vme->is_loaded = true;
  vme->pinned = false;
  insert_vme (& thread_current ()->vm, vme);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Add file pointer to file descriptor table of the thread. */
int process_add_file (struct file *f)
{
  struct thread *t = thread_current ();
  int fd = t->fd_next;

  t->fd_table[fd] = f;
  t->fd_next = t->fd_next + 1;

  return fd;
}

/* Return file pointer from file descriptor table of the thread. */
struct file *process_get_file (int fd)
{
  struct thread *t = thread_current ();

  if (1 < fd && fd < t->fd_next)
    return t -> fd_table[fd];

  else 
    return NULL;
}

/* Close file and initialize the entry allocated to the file descriptor. */
void process_close_file (int fd)
{
  struct thread *t = thread_current ();
  struct file *f;

  if (1 < fd && fd < t->fd_next)
  {
    f = process_get_file (fd);
    file_close (f);
    t -> fd_table[fd] = NULL;
  }
}

/* Remove vm entries, page table entries, and ,if dirty bit is 1, save the change to the disk. */
void do_munmap (struct mmap_file *mmf)
{
  struct list *vme_list = &mmf->vme_list;
  struct vm_entry *vme;
  void *vaddr;
  struct file *file = mmf->file;

  struct list_elem *e = list_begin (vme_list); 
  while (e != list_end (vme_list))
  {
	vme = list_entry (e, struct vm_entry, mmap_elem);
	vaddr = vme->vaddr;
	if (pagedir_is_dirty (thread_current ()->pagedir, vaddr))
	{
	  lock_acquire (&filesys_lock);
	  file_write_at (file, vaddr, vme->read_bytes, vme->offset);
	  lock_release (&filesys_lock);
	}
	e = list_remove (e);
	free_page (pagedir_get_page(thread_current ()->pagedir, vaddr));
	delete_vme (& thread_current ()->vm, vme);
	free (vme);
  }

  free (mmf);
  file_close (file);
}

bool handle_mm_fault (struct vm_entry *vme)
{
  //void *kaddr = palloc_get_page (PAL_USER);
  struct page *page = alloc_page (PAL_USER);
  void *kaddr = page->kaddr;
  bool success = false;
  if (kaddr == NULL) return false;

  //printf ("load page : %p, vme : %p, vaddr %p, type : %d\n", page, vme, vme->vaddr, vme->type);
  switch (vme->type)
  {
	case VM_BIN:
	case VM_FILE:
	  success = load_file (kaddr, vme);
	  break;

	case VM_ANON:
	  swap_in (vme->swap_slot, kaddr);
	  success = true;
	  break;

	default:
	  return false;
	  break;
  }
  if (success)
  {
	success = install_page (vme->vaddr, kaddr, vme->writable);
	if (success)
	{
	  vme->is_loaded = true;
	  page->vme = vme;
	}
  }
  else
	free_page (kaddr);
  //printf ("installed(success : %d) vaddr:0x%x, kaddr:0x%x, writable:%d\n",  success, vme->vaddr, kaddr, vme->writable);
  return success;
}
