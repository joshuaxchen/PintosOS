#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

enum inode_flags {
	INODE_ISDIR = 001
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t flags;						/* Flags. */
	block_sector_t blocks[125];         /* doubly indirect blocks. */
};

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	block_sector_t sector;              /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct lock lock;                   /* Lock for the file. */
	struct inode_disk data;             /* Inode content. */
};

static block_sector_t
init_sector(void) {
	// printf("creating new data sector\n");
	block_sector_t sector;
	if (!free_map_allocate(1, &sector))
		return -1;
	// printf("after allocate\n");
	static char zeros[BLOCK_SECTOR_SIZE];
	// printf("before write\n");
	block_write(fs_device, sector, zeros);
	// printf("after write\n");
	return sector;
}

static block_sector_t
init_indirect_sector(void) {
	// printf("creating new indirect sector\n");
	block_sector_t sector;
	if (!free_map_allocate(1, &sector))
		return -1;
	// printf("successfully allocated from free map\n");
	block_sector_t data[BLOCK_SECTOR_SIZE / sizeof(block_sector_t)];
	size_t i;
	for (i = 0; i < BLOCK_SECTOR_SIZE / sizeof(block_sector_t); i++)
		data[i] = -1;
	block_write(fs_device, sector, data);
	// printf("finished creating new indirect sector\n");
	return sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector(struct inode *inode, off_t pos) {
	// printf("trying to get sector from bytes on file %d pos %d\n", inode->sector, pos);
	ASSERT(inode != NULL);
	const size_t NUM_PTRS = BLOCK_SECTOR_SIZE / sizeof(block_sector_t);
	size_t first_idx = pos / NUM_PTRS / NUM_PTRS / BLOCK_SECTOR_SIZE;
	size_t second_idx = (pos / NUM_PTRS / BLOCK_SECTOR_SIZE) % NUM_PTRS;
	size_t third_idx = (pos / BLOCK_SECTOR_SIZE) % NUM_PTRS;
	if (inode->data.blocks[first_idx] == (block_sector_t)-1) {
		inode->data.blocks[first_idx] = init_indirect_sector();
		if (inode->data.blocks[first_idx] == (block_sector_t)-1)
			return -1;
		block_write(fs_device, inode->sector, &inode->data);
	}
	// printf("got first block as %d at index %d\n", inode->data.blocks[first_idx], first_idx);
	block_sector_t *indirect_block = malloc(BLOCK_SECTOR_SIZE);
	if (!indirect_block)
		return -1;
	block_read(fs_device, inode->data.blocks[first_idx], indirect_block);
	if (indirect_block[second_idx] == (block_sector_t)-1) {
		indirect_block[second_idx] = init_indirect_sector();
		if (indirect_block[second_idx] == (block_sector_t)-1) {
			free(indirect_block);
			return -1;
		}
		block_write(fs_device, inode->data.blocks[first_idx], indirect_block);
	}
	block_sector_t second_block_sector = indirect_block[second_idx];
	// printf("got second block as %d at index %d\n", second_block_sector, second_idx);
	block_read(fs_device, second_block_sector, indirect_block);
	if (indirect_block[third_idx] == (block_sector_t)-1) {
		indirect_block[third_idx] = init_sector();
		// printf("inited last block as %d\n", indirect_block[third_idx]);
		if (indirect_block[third_idx] == (block_sector_t)-1) {
			free(indirect_block);
			return -1;
		}
		// printf("writing block to %d\n", second_block_sector);
		block_write(fs_device, second_block_sector, indirect_block);
	}
	// printf("freeing indirect block %p\n", indirect_block);
	block_sector_t result = indirect_block[third_idx];
	free(indirect_block);
	// printf("got sector as %d at index %d\n", result, third_idx);
	return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init(void) {
	list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create(block_sector_t sector, off_t length) {
	struct inode *inode;
	ASSERT (length >= 0);
	/* If this assertion fails, the inode structure is not exactly
	   one sector in size, and you should fix that. */
	ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);
	inode = malloc(sizeof *inode);
	if (!inode)
		return false;
	inode->data.length = length;
	inode->data.magic = INODE_MAGIC;
	inode->data.flags = 0;
	lock_init(&inode->lock);
	size_t i;
	for (i = 0; i < sizeof(inode->data.blocks) / sizeof(block_sector_t); i++)
		inode->data.blocks[i] = -1;
	block_write(fs_device, sector, &inode->data);

	if (length > 0) {
		// printf("preallocating %d bytes for new file %d\n", length, sector);
		inode->sector = sector;
		for (i = 0; i < (size_t)(length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE; i++) {
			// printf("preallocating byte at location %d\n", i * BLOCK_SECTOR_SIZE);
			byte_to_sector(inode, i * BLOCK_SECTOR_SIZE);
		}
	}

	free(inode);
	return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector) {
	// printf("trying to open sector %d\n", sector);
	if (sector == (block_sector_t)-1)
		return NULL;
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
			e = list_next(e)) {
		inode = list_entry(e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen(inode);
			return inode; 
		}
	}

	// printf("sector does not exist %d\n", sector);

	/* Allocate memory. */
	inode = malloc(sizeof *inode);
	if (inode == NULL)
		return NULL;

	// printf("allocated inode\n");

	/* Initialize. */
	list_push_front(&open_inodes, &inode->elem);
	// printf("pushed onto list\n");
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	// printf("initing lock\n");
	lock_init(&inode->lock);
	// printf("reading block\n");
	block_read(fs_device, inode->sector, &inode->data);
	// printf("finished opening\n");
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode) {
	return inode->sector;
}

static void
remove_data_blocks(struct inode *inode) {
	block_sector_t *first_indirect_block = malloc(BLOCK_SECTOR_SIZE);
	block_sector_t *second_indirect_block = malloc(BLOCK_SECTOR_SIZE);
	size_t i, j, k;
	for (i = 0; i < sizeof(inode->data.blocks) / sizeof(block_sector_t); i++) {
		if (inode->data.blocks[i] == (block_sector_t)-1)
			continue;
		block_read(fs_device, inode->data.blocks[i], first_indirect_block);
		for (j = 0; j < BLOCK_SECTOR_SIZE / sizeof(block_sector_t); j++) {
			if (first_indirect_block[j] == (block_sector_t)-1)
				continue;
			block_read(fs_device, first_indirect_block[j], second_indirect_block);
			for (k = 0; k < BLOCK_SECTOR_SIZE / sizeof(block_sector_t); k++) {
				if (second_indirect_block[k] == (block_sector_t)-1)
					continue;
				free_map_release(second_indirect_block[k], 1);
			}
			free_map_release(first_indirect_block[j], 1);
		}
		free_map_release(inode->data.blocks[i], 1);
	}
	free(first_indirect_block);
	free(second_indirect_block);
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close(struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove(&inode->elem);
 
		/* Deallocate blocks if removed. */
		if (inode->removed) {
			free_map_release(inode->sector, 1);
			remove_data_blocks(inode);
		}

		free(inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove(struct inode *inode) {
	ASSERT(inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {
	// printf("reading from inode %d size %d offset %d length %d\n", inode->sector, size, offset, inode_length(inode));
	if (inode_length(inode) <= offset)
		return 0;
	// printf("actually reading\n");
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	// inode_lock(inode);
	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector(inode, offset);
		// printf("trying to read from sector %d\n", sector_idx);
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length(inode) - offset;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			block_read(fs_device, sector_idx, buffer + bytes_read);
		} else {
			/* Read sector into bounce buffer, then partially copy
			   into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc(BLOCK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			block_read(fs_device, sector_idx, bounce);
			memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	// inode_unlock(inode);
	free(bounce);
	// printf("successfully read data %d\n", *(char*)buffer_);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at(struct inode *inode, const void *buffer_, off_t size, off_t offset) {
	// printf("writing to inode %d size %d offset %d\n", inode->sector, size, offset);
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	if (inode->deny_write_cnt)
		return 0;

	// inode_lock(inode);
	if (inode_length(inode) < offset + size)
		inode_set_length(inode, offset + size);

	while (size > 0) {
		/* Sector to write, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector(inode, offset);
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* bytes left in sector */
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < sector_left ? size : sector_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
			/* Write full sector directly to disk. */
			block_write(fs_device, sector_idx, buffer + bytes_written);
        } else {
			/* We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (BLOCK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left)
				block_read(fs_device, sector_idx, bounce);
			else
				memset(bounce, 0, BLOCK_SECTOR_SIZE);
			memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
			block_write(fs_device, sector_idx, bounce);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	// inode_unlock(inode);
	free(bounce);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write(struct inode *inode) {
	inode->deny_write_cnt++;
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write(struct inode *inode) {
	ASSERT(inode->deny_write_cnt > 0);
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Sets the length, in bytes, of INODE's data. */
void
inode_set_length(struct inode *inode, const off_t length) {
	if (inode->data.length != length) {
		inode->data.length = length;
		block_write(fs_device, inode->sector, &inode->data);
	}
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length(const struct inode *inode) {
	return inode->data.length;
}

/* Sets the is_dir flag to 1. */
void
inode_set_dir(struct inode *inode) {
	// printf("setting directory of %d to true\n", inode->sector);
	if ((inode->data.flags & INODE_ISDIR) == 0) {
		inode->data.flags |= INODE_ISDIR;
		block_write(fs_device, inode->sector, &inode->data);
	}
}

/* Checks for the is_dir flag. */
bool
inode_isdir(struct inode *inode) {
	return (inode->data.flags & INODE_ISDIR) > 0;
}

/* Acquires the lock for the inode */
void
inode_lock(struct inode *inode) {
	lock_acquire(&inode->lock);
}

/* Releases the lock for the inode */
void
inode_unlock(struct inode *inode) {
	lock_release(&inode->lock);
}
