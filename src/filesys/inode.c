#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_ENTRIES 124
#define INDIRECT_BLOCK_ENTRIES 128

static struct lock inode_lock;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[124];               /* Not used. */
    int is_dir;
    //block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
    //block_sector_t indirect_block_sec;
    //block_sector_t double_indirect_block_sec;
    //uint32_t unused[2];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
  /*if (pos < inode->data.length){
    if (pos/BLOCK_SECTOR_SIZE < DIRECT_BLOCK_ENTRIES)
      return inode->data.direct_map_table[pos/BLOCK_SECTOR_SIZE];*/
    /*else if (pos/BLOCK_SECTOR_SIZE -= DIRECT_BLOCK_ENTRIES < INDIRECT_BLOCK_ENTRIES){
      //block_sector_t indirect_map_table[INDIRECT_BLOCK_ENTRIES];
      block_sector_t *indirect_map_table = malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device,inode->data.indirect_block_sec,indirect_map_table);
      block_sector_t sec = indirect_map_table[pos/BLOCK_SECTOR_SIZE];
      free(indirect_map_table);
      return sec;
    }
    else{
      pos -= INDIRECT_BLOCK_ENTRIES;
      //block_sector_t double_indirect_map_table[INDIRECT_BLOCK_ENTRIES];
      block_sector_t *double_indirect_map_table = malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device,inode->data.double_indirect_block_sec,double_indirect_map_table);
      //block_sector_t indirect_map_table[INDIRECT_BLOCK_ENTRIES];
      block_sector_t *indirect_map_table = malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device,double_indirect_map_table[pos/INDIRECT_BLOCK_ENTRIES],indirect_map_table);
      block_sector_t sec = indirect_map_table[pos%INDIRECT_BLOCK_ENTRIES];
      free(double_indirect_map_table);
      free(indirect_map_table);
      return sec;
      //return indirect_map_table[pos%INDIRECT_BLOCK_ENTRIES];
    }*/
    /*else return -1;
    }
  else
    return -1;*/
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  lock_init(&inode_lock);
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  //ASSERT ()

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = 0;
      /*
      static char zeros[BLOCK_SECTOR_SIZE];
      bool alloc_success;

      for (int i=0; i < DIRECT_BLOCK_ENTRIES; i++){
        if (sectors == 0) break;
        alloc_success = free_map_allocate(1,&disk_inode->direct_map_table[i]);
        if(alloc_success)
        {
          block_write (fs_device, disk_inode->direct_map_table[i], zeros);
          sectors--;
        }
      }*/
      /*
      if (sectors > 0){
        success = free_map_allocate(1,&disk_inode->indirect_block_sec);
        block_sector_t indirect_map_table[INDIRECT_BLOCK_ENTRIES];
        for (int j=0; j < INDIRECT_BLOCK_ENTRIES; j++){
          if (sectors == 0) break;
          success = free_map_allocate(1,&indirect_map_table[j]);
          block_write (fs_device, indirect_map_table[j], zeros);
          sectors--;
        }
        block_write(fs_device,disk_inode->indirect_block_sec,indirect_map_table);
      }
      if (sectors > 0){
        success = free_map_allocate(1,&disk_inode->double_indirect_block_sec);
        block_sector_t double_indirect_map_table[INDIRECT_BLOCK_ENTRIES];
        for (int k=0; k < INDIRECT_BLOCK_ENTRIES; k++){
          if (sectors == 0) break;
          success = free_map_allocate(1,&double_indirect_map_table[k]);
          block_sector_t dindirect_map_table[INDIRECT_BLOCK_ENTRIES];
          for (int l=0; l < INDIRECT_BLOCK_ENTRIES; l++){
            if (sectors == 0) break;
            success = free_map_allocate(1,&dindirect_map_table[l]);
            block_write (fs_device, dindirect_map_table[l], zeros);
            sectors--;
          }
          block_write(fs_device,double_indirect_map_table[k],dindirect_map_table);
        }
        block_write(fs_device,disk_inode->double_indirect_block_sec,double_indirect_map_table);
      }*/
      //if (alloc_success) 
      if (free_map_allocate(sectors,&disk_inode->start))
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Get on-disk inode structure by get_disk_inode()*/
          //struct inode_disk *disk_inode = &inode->data;

          /* Deallocate each blocks by free_inode_sectors() */
          /*int i,j = 0;
          while(i< bytes_to_sectors(inode->data.length)){
            free_map_release(inode->data.direct_map_table[i],1);
            i++;
          }*/

          /* Deallocate on-disk inode by free_map_release() */
          /*free_map_release (inode->sector, 1);
          free (&inode->data);*/

          /*
          i = 0;
          block_sector_t indirect_map_table[INDIRECT_BLOCK_ENTRIES];
          block_read(fs_device,inode->data.indirect_block_sec,indirect_map_table);
          free_map_release(disk_inode->indirect_block_sec,1);
          while(indirect_map_table[i] != NULL){
            free_map_release(indirect_map_table[i],1);
          }
          i = 0;
          block_sector_t double_indirect_map_table[INDIRECT_BLOCK_ENTRIES];
          block_read(fs_device,inode->data.double_indirect_block_sec,double_indirect_map_table);
          free_map_release(disk_inode->double_indirect_block_sec,1);
          while(double_indirect_map_table[i] != NULL){
            block_sector_t d_indirect_map_table[INDIRECT_BLOCK_ENTRIES];
            block_read(fs_device,double_indirect_map_table[i],double_indirect_map_table);
            free_map_release(double_indirect_map_table[i],1);
            j = 0;
            while(d_indirect_map_table[j] != NULL){
              free_map_release(d_indirect_map_table[j],1);
              j++;
            }
          }*/
             
          free_map_release (inode->sector, 1);
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length));
        }
      
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      ASSERT(sector_idx >= 0);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read data from the buffer cache. */
          cache_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  /* Acquire some lock to avoid contention on inode */
  lock_acquire(&inode_lock);
  /*
  struct inode_disk *disk_inode = &inode->data;
  int old_length = disk_inode->length;
  int write_end = offset +  size - 1;
  static char zeros[BLOCK_SECTOR_SIZE];

  if(write_end > old_length -1 ){
    // When size of file is updated, Update inode 
    //block_sector_t sector = byte_to_sector(inode,offset);
    int n = DIV_ROUND_UP (write_end - old_length, BLOCK_SECTOR_SIZE);
    block_sector_t sector = byte_to_sector(inode,old_length);
    ASSERT(sector >= 0);
    block_sector_t *map;
    for (int i = 1; i<=n; i++){
      map = &sector + 4*i;
      if(!free_map_allocate(1,map)) return 0;
      block_write (fs_device, *map, zeros);
      disk_inode -> length = disk_inode->length + BLOCK_SECTOR_SIZE;
    }
  }*/
  /* Release lock */
  lock_release(&inode_lock);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      ASSERT(sector_idx >= 0);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write data to buffer cache rather than to disk. */
          cache_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_isdir (const struct inode *inode)
{
  return inode->data.is_dir;
}

void inode_setdir (struct inode *inode, int flag)
{
  inode->data.is_dir = flag;
}