#ifndef FRAME_H
#define FRMAE_H

#include "vm/page.h"
#include <list.h>
#include <stdbool.h>

struct list lru_list;
struct lock lru_lock;

void lru_list_init (void);
void add_page_to_lru_list (struct page *page);
void del_page_from_lru_list (struct page *page);
struct page *alloc_page (enum palloc_flags flags);
void free_page (void *kaddr);
void _free_page (struct page *page);
void *try_to_free_pages (enum palloc_flags flags);
void pin_address (void *buffer, size_t size);
void unpin_address (void *buffer, size_t size);

#endif
