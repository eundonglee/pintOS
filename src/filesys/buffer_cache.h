#ifndef BUFFER_CACHE_H
#define BUFFER_CACHE_H

#include "filesys/inode.h"
#include "devices/block.h"
#include "threads/synch.h"


/* Manages a buffer cache entry. */
struct buffer_head
{
  bool dirty;
  bool used;
  bool clock;
  block_sector_t sector;
  void *buffer_cache;
  struct lock bc_lock;
};

void bc_init (void);
void bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
void bc_write (block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs);
void bc_term (void);

#endif
