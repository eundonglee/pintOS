#include "vm/page.h"
#include <hash.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED);

/* Initialize vm hash table. */
void vm_init (struct hash *vm)
{
  hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

/* Insert vm entry into vm hash table. */
void insert_vme (struct hash *vm, struct vm_entry *vme)
{
  hash_insert (vm, &vme->elem);
}

/* Delete vm entry from vm hash table. */
void delete_vme (struct hash *vm, struct vm_entry *vme)
{
  hash_delete (vm, &vme->elem);
}

/* Return address of the vm entry which has the virtual address. */
struct vm_entry *find_vme (void *vaddr)
{
  struct vm_entry vme;
  struct hash_elem *e;

  vme.vaddr = pg_round_down (vaddr);
  e = hash_find (& thread_current ()->vm, & vme.elem);
  if (e == NULL) return NULL;
  else return hash_entry (e, struct vm_entry, elem);
}

/* Destroy all vm entry. */
void vm_destroy (struct hash *vm)
{
  hash_destroy (vm, vm_destroy_func);
}

/* Hash function for hash table initialization. */
static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
  return hash_int ((int) vme->vaddr);
}

/* If virtual address of the vm entry A is less than that of B, return TRUE. Otherwise, return FALSE. */
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct vm_entry *vme_a = hash_entry (a, struct vm_entry, elem);
  struct vm_entry *vme_b = hash_entry (b, struct vm_entry, elem);

  return (vme_a->vaddr < vme_b->vaddr)? true: false;
}

/* Destructor function for destroying vm entry. */
static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
  uint32_t *pd = thread_current ()->pagedir; 

  free_page (pagedir_get_page (pd, vme->vaddr));
  free (vme); 
}

/* Load file to physical memory. */
bool load_file (void *kaddr, struct vm_entry *vme)
{
  //printf ("load kaddr : 0x%x, vme : 0x%x, read_bytes : %d, zero_bytes : %d\n", kaddr, vme, vme->read_bytes, vme->zero_bytes);
  lock_acquire (& filesys_lock);
  size_t actual_read = file_read_at (vme->file, kaddr, vme->read_bytes, vme->offset);
  lock_release (& filesys_lock);
  if (actual_read != vme->read_bytes) return false;
  memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
  return true;
}
