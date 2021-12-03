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
	// Driver start: Jimmy
	// get directory for name
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
				// open root
			} else {
				buffer[buffer_idx] = 0;
				buffer_idx = 0;
				struct inode *inode;
				// try to find name
				if (!*dir || !dir_lookup(*dir, buffer, &inode)) {
					if (*dir)
						dir_close(*dir);
					*dir = NULL;
					return false;
				}
				// open directory for name
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
	// found file name
	return *dir != NULL;
	// Driver end: Jimmy
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create(const char *name, off_t initial_size) {
	// Driver start: Joshua
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
	// Driver end: Joshua
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name) {
	// Driver start: Ankit
	// try to open
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	if (!get_directory(&dir, name, fname)) {
		// failed to find directory
		dir_close(dir);
		return NULL;
	}
	struct inode *inode = NULL;

	if (fname[0] != 0) {
		dir_lookup(dir, fname, &inode);
		dir_close(dir);
	} else {
		inode = dir_get_inode(dir);
		free(dir);
		// manually unlocking because dir_close was not called
	}
	// finished open

	return file_open(inode);
	// Driver end: Ankit
}

// Driver start: Ankit, Jimmy
/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove(const char *name) {
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = get_directory(&dir, name, fname) && dir_remove(dir, fname);
	if (dir)
		dir_close(dir); 

	return success;
}

/* Changes the directory */
bool
filesys_chdir(const char *name) {
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = get_directory(&dir, name, fname);
	if (success) {
		struct inode *inode = NULL;
		success = dir_lookup(dir, fname, &inode);
		if (success)
			thread_current()->process_info.curr_dir = inode_get_inumber(inode);
		if (inode)
			inode_close(inode);
	}
	if (dir)
		dir_close(dir);
	return success;
}
// Driver end: Ankit, Jimmy
/* Makes a directory */
bool
filesys_mkdir(const char *name) {
	// driver start: Joshua
	block_sector_t inode_sector = 0;
	struct dir *dir = get_curr_dir();
	char fname[NAME_MAX + 1];
	bool success = (get_directory(&dir, name, fname)
			&& free_map_allocate(1, &inode_sector)
			&& inode_create(inode_sector, 2));
	if (success) {
		struct dir *new_dir = dir_open(inode_open(inode_sector));
		dir_close(new_dir);
		// add inode into dir
		success = dir_add(dir, fname, inode_sector);
		// check if successful 
	}
	if (!success && inode_sector != 0) 
		free_map_release(inode_sector, 1);
	if (dir)
		dir_close(dir);
	// mkdir finished

	return success;
	// driver end: joshua
}

/* Formats the file system. */
static void
do_format(void) {
	// driver start: Ankit
	// format file system
	free_map_create();
	if (!dir_create(ROOT_DIR_SECTOR, 16))
		PANIC("root directory creation failed");
	free_map_close();
	// Driver end: Ankit
}
