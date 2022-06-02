#include "off_t.h"
#include <stdbool.h>
#include "list.h"
#include "devices/block.h"

struct buffer_head {
    bool dirty;               /* dirty flag */
    bool in_use;              /* entry is being used or not */
    bool access;              /* entry is accessed recently or not */
    block_sector_t sector;    /* on-disk location */
    void *data;               /* virtual address of associated buffer cache entry */

    /* For buffer head table */
    struct list_elem bhead_elem;
};

void cache_init(void);

void cache_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
void cache_write (block_sector_t sector_idx, void *buffer, off_t bytes_write, int chunk_size, int sector_ofs);

void cache_terminate (void);

struct buffer_head *cache_select_victim (void);
struct buffer_head *cache_lookup (block_sector_t sector);
void cache_flush_entry (struct buffer_head *p_flush_entry);
void cache_flush_all_entries (void);
