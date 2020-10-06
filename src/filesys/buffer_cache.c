#include <string.h>
#include <stdio.h>
#include "filesys/buffer_cache.h"
#include "filesys/filesys.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Number of buffer cache entries. */
#define BUFFER_CACHE_ENTRY_NB 64

/* Pointer to buffer cache memory area. */
void *p_buffer_cache;

/* Array of buffer heads. */
struct buffer_head buffer_heads[BUFFER_CACHE_ENTRY_NB];

/* Pointer to lru clock hand. */
struct buffer_head *clock_hand;


static struct buffer_head *bc_select_victim (void);
static struct buffer_head *get_next_buffer_head_clock (void);

/* Initialize buffer heads.*/
void bc_init (void)
{
  int i;
  struct buffer_head *bh;

  p_buffer_cache = malloc(BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE);
  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
	bh = & buffer_heads[i];
	bh->dirty = false;
	bh->used = false;
	bh->clock = false;
	bh->buffer_cache = p_buffer_cache + i * BLOCK_SECTOR_SIZE;
	lock_init (& bh->bc_lock);
  }
  clock_hand = & buffer_heads[0];
}

/* Return buffer head which corresponds to the block sector index.*/
static struct buffer_head *bc_lookup (block_sector_t sector)
{
  int i;
  struct buffer_head *bh;

  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
	bh = & buffer_heads[i];
	if (sector == bh->sector)
	  return bh;
  }
  return NULL;
}

/* Read data from filesys to buffer with using buffer cache. */
void bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{
  struct buffer_head *bh;
  void *buffer_cache;

  /* Find buffer head which corresponds to the sector index. */
  bh = bc_lookup (sector_idx);

  /* If the sector is not in buffer cache, read it from the filesys to buffer cache. */
  if (bh == NULL)
  {
	bh = bc_select_victim ();
	lock_acquire (& bh->bc_lock);
	buffer_cache = bh->buffer_cache;
	block_read (fs_device, sector_idx, buffer_cache);
	bh->dirty = false;
	bh->sector = sector_idx;
  }

  else
  {
	lock_acquire (& bh->bc_lock);
	buffer_cache = bh->buffer_cache;
  }

  /* Read data from buffer cache to buffer. */
  memcpy (buffer + bytes_read, buffer_cache + sector_ofs, chunk_size);
  bh->clock = true;
  lock_release (& bh->bc_lock);
}

/* Write data from buffer to filesys with using buffer cache. */
void bc_write (block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
  struct buffer_head *bh;
  void *buffer_cache;

  /* Find buffer head which corresponds to the sector index. */
  bh = bc_lookup (sector_idx);

  if (bh == NULL)
  {
	bh = bc_select_victim ();
	lock_acquire (& bh->bc_lock);
	buffer_cache = bh->buffer_cache;
	block_read (fs_device, sector_idx, buffer_cache);
	bh->sector = sector_idx;
  }

  else
  {
	lock_acquire (& bh->bc_lock);
	buffer_cache = bh->buffer_cache;
  }

  /* Write data from buffr to buffer cache. */
  memcpy (buffer_cache + sector_ofs, buffer + bytes_written, chunk_size);
  bh->dirty = true;
  bh->clock = true;
  lock_release (& bh->bc_lock);
}

/* Write data from buffer cache to filesys. */
static void bc_flush_entry (struct buffer_head *p_flush_entry)
{
  lock_acquire (& p_flush_entry->bc_lock);
  block_write (fs_device, p_flush_entry->sector, p_flush_entry->buffer_cache);
  p_flush_entry->dirty = false;
  lock_release (& p_flush_entry->bc_lock);
}

/* Write data from all buffer caches to filesys. */
static void bc_flush_all_entries (void)
{
  int i;
  struct buffer_head *bh;

  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
	bh = & buffer_heads[i];
	if (bh->dirty == true)
	  bc_flush_entry (bh);
  }
}

/* Select a victim buffer cache entry with using lru algorithm. */
static struct buffer_head *bc_select_victim (void)
{
  struct buffer_head *clock_hand_start = clock_hand;
  struct buffer_head *bh;
  struct buffer_head *victim = NULL;

  bh = clock_hand_start;
  do
  {
	if (bh->used == false)
	{
	  bh->used = true;
	  victim = bh;
	  return victim;
	}

	if (bh->clock == false)
	{
	  victim = bh;
	  break;
	}

	else
	  bh->clock = false;

	/* Advnace. */
	bh = get_next_buffer_head_clock ();
  } 
  while (bh != clock_hand_start);

  if (victim == NULL)
	victim = & buffer_heads[0];

  if (victim->dirty == true)
	bc_flush_entry (victim); 

  return victim;
}

/* Flush and terminate all buffer cache entries */
void bc_term (void)
{
  bc_flush_all_entries ();
  free (p_buffer_cache);
}

/* Return the next lru clock hand. */
static struct buffer_head *get_next_buffer_head_clock (void)
{
  if (clock_hand - & buffer_heads[0] + 1 < BUFFER_CACHE_ENTRY_NB)
	return ++clock_hand;
  else
  {
	clock_hand = & buffer_heads[0];
	return clock_hand;
  }
}
