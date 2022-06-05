#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "threads/synch.h"
#include "list.h"
#include "threads/malloc.h"
#include "devices/block.h"
#include "filesys.h"

static struct lock cache_lock;
static struct list buffer_head_table;

void cache_init(void) {
    lock_init(&cache_lock);
    list_init(&buffer_head_table);

    /* Allocate memory for 64 blocks of buffer cache */
    for(int i=0; i < 64; i++) {
        struct buffer_head *b = malloc(sizeof(struct buffer_head));
        b->dirty = false;
        b->in_use = false;
        b->access = false;
        b->data = (struct block *)malloc(BLOCK_SECTOR_SIZE);
        
        list_push_back(&buffer_head_table, &b->bhead_elem);
    }
}

void cache_read (block_sector_t sector_idx, void *buffer, off_t bytes_read,
                int chunk_size, int sector_ofs) {
    lock_acquire(&cache_lock);
    
    struct buffer_head *b = cache_lookup(sector_idx);
    if (b == NULL) {  // cache miss
       b = cache_select_victim();
       
       b->in_use = true;
       b->sector = sector_idx;
       b->dirty = false;
       block_read(fs_device, sector_idx, b->data);
    }

    b->access = true;
    memcpy(buffer + bytes_read, b->data, BLOCK_SECTOR_SIZE);
    lock_release(&cache_lock);
}

void cache_write (block_sector_t sector_idx, void *buffer, off_t bytes_written,
                 int chunk_size, int sector_ofs) {
    lock_acquire(&cache_lock);

    struct buffer_head *b = cache_lookup(sector_idx);
    if (b == NULL) {
        b = cache_select_victim();

        b->in_use = true;
        b->sector = sector_idx;
        b->dirty = false;
        block_read(fs_device, sector_idx, b->data);
    }

    b->access = true;
    b->dirty = true;
    memcpy(b->data, buffer + bytes_written, BLOCK_SECTOR_SIZE);
    lock_release(&cache_lock);
}

void cache_terminate (void) {
    cache_flush_all_entries();

    struct list_elem *e;
    for (e = list_begin(&buffer_head_table); e != list_end(&buffer_head_table); 
        e = list_next(e)) {
        struct buffer_head *b = list_entry(e, struct buffer_head, bhead_elem);
        free(b->data);
    }
}

struct buffer_head *cache_select_victim (void) {
    ASSERT(lock_held_by_current_thread(&cache_lock));
    struct list_elem *e = list_begin(&buffer_head_table);
    struct buffer_head *b;

    while(true) {
        b = list_entry(e, struct buffer_head, bhead_elem);

        if (!b->in_use) return b;

        if(b->access) b->access = false; // second chance
        else break;

        if(e == list_end(&buffer_head_table)) e = list_begin(&buffer_head_table);
        else e = list_next(e);
    }

    if(b->dirty) cache_flush_entry(b);
    return b;
}

struct buffer_head *cache_lookup (block_sector_t sector) {
    struct list_elem *e;
    for (e = list_begin(&buffer_head_table); e != list_end(&buffer_head_table); 
        e = list_next(e)) {
        struct buffer_head *b = list_entry(e, struct buffer_head, bhead_elem);
        if (b->sector == sector) return b;
    }
    return NULL;
}

void cache_flush_entry (struct buffer_head *p_flush_entry) {
    ASSERT(lock_held_by_current_thread(&cache_lock));
    ASSERT(p_flush_entry != NULL);
    ASSERT(p_flush_entry->in_use == true);

    if(p_flush_entry->dirty) {
        block_write(fs_device, p_flush_entry->sector, p_flush_entry->data);
        p_flush_entry->dirty = false;
    }
}

void cache_flush_all_entries (void) {
    lock_acquire(&cache_lock);

    struct list_elem *e;
    for (e = list_begin(&buffer_head_table); e != list_end(&buffer_head_table); 
        e = list_next(e)) {
        struct buffer_head *b = list_entry(e, struct buffer_head, bhead_elem);
        if(!b->in_use) continue;
        cache_flush_entry(b);
    }
}

