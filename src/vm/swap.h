#ifndef SWAP_H
#define SWAP_H

#include <stddef.h>

#define SWAP_ERROR (SIZE_MAX)

void swap_init (void);
void swap_in (size_t used_index, void *kaddr);
size_t swap_out (void *kaddr);
size_t swap_slot_max (void);

#endif
