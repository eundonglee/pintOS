#include "vm/swap.h"
#include <bitmap.h>
#include <stddef.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

struct lock swap_partition_lock;

struct block *block_swap;
struct bitmap *swap_bitmap;
size_t swap_slot_count;

/* Initialize swap space and swap bitmap. */
void swap_init (void)
{
  block_swap = block_get_role (BLOCK_SWAP);
  lock_init (& swap_partition_lock);
  /* Block size is expressed in block sector size(512bytes).
	 Swap slot size(4KB) is 8 times of the block sector. */
  swap_slot_count = block_size (block_swap) / 8;
  swap_bitmap = bitmap_create (swap_slot_count);
}

void swap_in (size_t used_index, void *kaddr)
{
  int read_count;
  block_sector_t sector;
  void *buffer;

  //printf ("index : %d\n", used_index);
  lock_acquire (& swap_partition_lock);

  sector = 8 * used_index;
  buffer = kaddr;
  for (read_count = 0; read_count != 8; read_count++)
  {
	block_read (block_swap, sector, buffer);
	sector++;
	buffer += 512;
  }

  lock_release (& swap_partition_lock);
  bitmap_set (swap_bitmap, used_index, 0);
}

size_t swap_out (void *kaddr)
{
  size_t swap_pos;
  int write_count;
  block_sector_t sector;
  void *buffer;

  swap_pos = bitmap_scan_and_flip (swap_bitmap, 0, 1, 0);
  if (swap_pos == BITMAP_ERROR || swap_pos > swap_slot_max ())
	return SWAP_ERROR;

  lock_acquire (& swap_partition_lock);

  sector = 8 * swap_pos;
  buffer = kaddr;
  for (write_count = 0; write_count != 8; write_count++)
  {
	block_write (block_swap, sector, buffer);
	sector++;
	buffer += 512;
  }

  lock_release (& swap_partition_lock);

  return swap_pos;
}

size_t swap_slot_max (void)
{
  return swap_slot_count - 1;
}
