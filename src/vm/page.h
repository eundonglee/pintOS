#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/palloc.h"

/* Types of virtual memory entry. */
enum vme_type
{
  VM_BIN,	  /* Load data from binary file. */
  VM_FILE,    /* Load data from mapped file. */
  VM_ANON     /* Load data form swap area.   */
};

struct vm_entry
{
  enum vme_type type;         /* Type of virtual memory. */  
  void *vaddr;                /* Virtual address managed by the vm_entry. */  
  bool writable;              /* If true, writing on the virtual address is allowed.
								 Otherwise, it is not. */
  bool is_loaded;             /* If true, the file is loaded on the physical memory. */
  bool pinned;				  /* If pinned, the page is not freed. */
  struct file *file;          /* File mapped to the virtual address. */
  struct list_elem mmap_elem; /* List element of the mmap list. */
  size_t offset;              /* Offset of the file to read. */
  size_t read_bytes;          /* Size of the data to load. */
  size_t zero_bytes;          /* Size of the page left to fill in with zeros. */
  size_t swap_slot;           /* Index of swap slot. */
  struct hash_elem elem;      /* Hash table element. */
};

struct mmap_file
{
  int mapid;                  /* ID of memory-mapped file. */
  struct file *file;          /* Address of memory-mapped file. */
  struct list_elem elem;      /* List element for memory-mapped file list. */
  struct list vme_list;       /* List of VM entries allocated for memory-mapped file. */
};

struct page
{
  void *kaddr;                /* Kernel virtual address allocated for the page. */
  struct vm_entry *vme;       /* VM entry which corresponds to the page. */
  struct thread *thread;      /* Thread which owns the page. */
  struct list_elem lru_elem;  /* List element for LRU list.  */
};

void vm_init (struct hash *vm);
void insert_vme (struct hash *vm, struct vm_entry *vme);
void delete_vme (struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme (void *vaddr);
void vm_destroy (struct hash *vm);
bool load_file (void *kaddr, struct vm_entry *vme);

#endif
