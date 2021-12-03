#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	fs_device = block_get_role(BLOCK_FILESYS);
	if (fs_device == NULL)
		PANIC("No file system device found, can't initialize file system.");

	inode_init();
	free_map_init();

	if (format) 
		do_format();

	free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done(void) {
	free_map_close();
}

static struct dir *
get_curr_dir(void) {
	return dir_open(inode_open(thread_current()->process_info.curr_dir));
}

static bool
get_directory(struct dir **dir, const char *name, char *buffer) {
	// printf("getting directory for name %s\n", name);
	if (name[0] == 0) {
		*dir = NULL;
		return false;
	}
	size_t name_idx = 0;
	size_t buffer_idx = 0;
	while (name[name_idx] != 0) {
		if (name[name_idx] == '/') {
			if (name[name_idx + 1] == 0 && buffer_idx != 0) {
				if (*dir)
					dir_close(*dir);
				*dir = NULL;
				return false;
			}
			if (name[name_idx + 1] == '/') {
				name_idx++;
				continue;
			}
			if (buffer_idx == 0) {
				if (*dir)
					dir_close(*dir);
				*dir = dir_open_root();
				// printf("opening root\n");
			} else {
				buffer[buffer_idx] = 0;
				buffer_idx = 0;
				struct inode *inode;
				// printf("trying to find name %s\n", buffer);
				if (!*dir || !dir_lookup(*dir, buffer, &inode)) {
					if (*dir)
						dir_close(*dir);
					*dir = NULL;
					return false;
				}
				// printf("opening directory for name %s\n", buffer);
				if (*dir)
					dir_close(*dir);
				*dir = dir_open(inode);
			}
		} else {
			if (buffer_idx == NAME_MAX) {
				if (*dir)
					dir_close(*dir);
				*dir = NULL;
				return false;
			}
			buffer[buffer_idx] = name[name_idx];
			buffer_idx++;
		}
		name_idx++;
	}
	buffer[buffer_idx] = 0;
	// printf("found file for name %s\n", buffer);
	return *dir != NULL;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create(const char *name, off_t initial_size) {
	// TODO: synchronization
	// printf("**********create %s\n", name);
	block_sector_t inode_sector = 0;
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = (get_directory(&dir, name, fname)
			&& free_map_allocate(1, &inode_sector)
			&& inode_create(inode_sector, initial_size)
			&& dir_add(dir, fname, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release(inode_sector, 1);
	if (dir)
		dir_close(dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name) {
	// TODO: synchronization
	// printf("trying to open %s\n", name);
	// printf("**********open %s\n", name);
	struct dir *dir = get_curr_dir();
	// printf("current dir is %d\n", inode_get_inumber(dir_get_inode(dir)));
	char fname[NAME_MAX + 1];
	if (!get_directory(&dir, name, fname)) {
		// printf("failed to find the directory\n");
		dir_close(dir);
		return NULL;
	}
	// printf("directory is %d with extra name %s\n", inode_get_inumber(dir_get_inode(dir)), fname);
	struct inode *inode = NULL;

	if (fname[0] != 0) {
		dir_lookup(dir, fname, &inode);
		dir_close(dir);
	} else {
		inode = dir_get_inode(dir);
		free(dir);
		// manually unlocking because dir_close was not called
		// inode_unlock(inode);
	}
	// printf("finished open\n");

	return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove(const char *name) {
	// printf("**********remove %s\n", name);
	// TODO: synchronization
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = get_directory(&dir, name, fname) && dir_remove(dir, fname);
	// printf("dir %p fname %s\n", dir, fname);
	if (dir)
		dir_close(dir); 

	return success;
}

/* Changes the directory */
bool
filesys_chdir(const char *name) {
	// TODO: synchronization
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = get_directory(&dir, name, fname);
	// printf("did it succeed in getting directory %d\n", success);
	if (success) {
		struct inode *inode = NULL;
		dir_lookup(dir, fname, &inode);
		thread_current()->process_info.curr_dir = inode_get_inumber(inode);
		inode_close(inode);
	}
	if (dir)
		dir_close(dir);
	return success;
}

/* Makes a directory */
bool
filesys_mkdir(const char *name) {
	// printf("**********mkdir %s\n", name);
	// TODO: synchronization
	block_sector_t inode_sector = 0;
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = (get_directory(&dir, name, fname)
			&& free_map_allocate(1, &inode_sector)
			&& inode_create(inode_sector, 2));
	if (success) {
		struct dir *new_dir = dir_open(inode_open(inode_sector));
		dir_close(new_dir);
		// printf("adding inode name %s into dir\n", fname);
		success = dir_add(dir, fname, inode_sector);
		// printf("did it succeed in adding %d\n", success);
	}
	if (!success && inode_sector != 0) 
		free_map_release(inode_sector, 1);
	if (dir)
		dir_close(dir);

	return success;
}

/* Formats the file system. */
static void
do_format(void) {
	// printf("Formatting file system...");
	free_map_create();
	if (!dir_create(ROOT_DIR_SECTOR, 16))
		PANIC("root directory creation failed");
	free_map_close();
	// printf("done.\n");
}
