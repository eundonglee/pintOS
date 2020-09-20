#include "vm/frame.h"
#include <list.h>
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

void lru_list_init (void)
{
  list_init (& lru_list);
  lock_init (& lru_lock);
}

void add_page_to_lru_list (struct page *page)
{
  list_push_back (& lru_list, & page->lru_elem);
}

void del_page_from_lru_list (struct page *page)
{
  list_remove (& page->lru_elem);
}

struct page *alloc_page (enum palloc_flags flags)
{
  void *kaddr;
  struct page *page;

  lock_acquire (& lru_lock);

  kaddr = palloc_get_page (flags);
  if (kaddr == NULL)
  {
	while (kaddr == NULL)
	  kaddr = try_to_free_pages (flags);
  }

  //printf ("allocated kaddr %p\n", kaddr);
  page = malloc (sizeof (struct page));

  page->kaddr = kaddr;
  page->thread = thread_current ();

  add_page_to_lru_list (page);

  lock_release (& lru_lock);

  return page;
}

void free_page (void *kaddr)
{
  struct list_elem *e;
  struct page *page;

  for (e = list_begin (& lru_list); e != list_end (& lru_list); e = list_next (e))
  {
	page = list_entry (e, struct page, lru_elem);
	if (page->kaddr == kaddr)
	{
	  _free_page (page);
	  break;
	}
  }
}

void _free_page (struct page *page)
{
  //printf ("page : %p kaddr : %p vaddr : %p type : %d\n", page, page->kaddr, page->vme->vaddr, page->vme->type);
  pagedir_clear_page (page->thread->pagedir, page->vme->vaddr);
  palloc_free_page (page->kaddr);
  del_page_from_lru_list (page);
  free (page);
}

void *try_to_free_pages (enum palloc_flags flags)
{
  struct list_elem *e;
  uint32_t *pd;
  struct page *page;
  struct vm_entry *vme;
  void *vaddr;
  void *kaddr;
  size_t swap_slot;

  for (e = list_begin (& lru_list); e != list_end (& lru_list);)
  {
	page = list_entry (e, struct page, lru_elem);

	vme = page->vme;
	pd = page->thread->pagedir;
	vaddr = vme->vaddr;
	kaddr = page->kaddr;
	if (vme->pinned == true)
	  e = list_next (e);
	else if (pagedir_is_accessed (pd, vaddr))
	{
	  e = list_next (e);
	  pagedir_set_accessed (pd, vaddr, 0);
	}
	else
	{
	  if (VM_BIN == vme->type)
	  {
	    //printf ("kaddr : %p vaddr : %p accessed : %d type: %d\n", page->kaddr, vaddr, pagedir_is_accessed (pd, vaddr), page->vme->type);
		if (pagedir_is_dirty (pd, vaddr))
		{		
		  swap_slot = swap_out (kaddr);
		  if (swap_slot != SWAP_ERROR)
		  {
			e = list_remove (e);
			_free_page (page);
			vme->swap_slot = swap_slot;
			vme->type = VM_ANON;
			vme->is_loaded = false;			
		  }
		  else 
			e = list_next (e);
		}
		else
		{
		  e = list_remove (e);
		  _free_page (page);
		  vme->is_loaded = false;
		}
	  }
	  else if (VM_FILE == vme->type)
	  {
		if (pagedir_is_dirty (pd, vaddr))
		{
	      //printf ("vme : %p kaddr : %p vaddr : %p type: %d\n", page->vme, page->kaddr, vaddr, page->vme->type);
		  //lock_acquire (& filesys_lock);
		  file_write_at (page->vme->file, kaddr, page->vme->read_bytes, page->vme->offset);
		  //lock_release (& filesys_lock);
		}
		e = list_remove (e);
		_free_page (page);
		vme->is_loaded = false;
	  }
	  else if (VM_ANON == vme->type)
	  {
		swap_slot = swap_out (kaddr);
		//printf ("swap_slot : %d, swap_slot_max : %d\n", swap_slot, swap_slot_max ());
		if (swap_slot != SWAP_ERROR)
		{
		  e = list_remove (e);
		  _free_page (page);
		  vme->swap_slot = swap_slot;
		  vme->is_loaded = false;
		} 
		else 
		  e = list_next (e);
	  }
	  else
		return NULL;
	}
  }
  return palloc_get_page (flags);
}

void pin_address (void *buffer, size_t size)
{
  struct vm_entry *vme;
  void *vaddr;

  for (vaddr = pg_round_down (buffer); vaddr < buffer + size; vaddr += PGSIZE)
  {
	vme = find_vme (vaddr);
	if (vme->is_loaded == false) 
	  handle_mm_fault (vme);
	vme->pinned = true;
  }
}

void unpin_address (void *buffer, size_t size)
{
  struct vm_entry *vme;
  void *vaddr;

  for (vaddr = pg_round_down (buffer); vaddr < buffer + size; vaddr += PGSIZE)
  {
	vme = find_vme (vaddr);
	vme->pinned = false;
  }
}
