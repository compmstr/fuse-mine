#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

/*
http://fuse.sourceforge.net/doxygen/annotated.html
http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/
http://www.ibm.com/developerworks/library/l-fuse/
http://www.cs.hmc.edu/~geoff/classes/hmc.cs135.201109/homework/fuse/fuse_doc.html

clang -ggdb fuse-mine.c `pkg-config fuse --cflags --libs` -o fuse-mine

--this will run in foreground(-f), and show debug info (-d)
[valgrind [--leak-check=full]] ./fuse-mine -f -d ~/share
*/

#define MEMFS_TYPE_DIR 0
#define MEMFS_TYPE_FILE 1
#define MEMFS_TYPE_LINK 2
#define MEMFS_DATA ((struct memfs_state *) fuse_get_context()->private_data)

struct memfs_file {
	char * name;
	unsigned long size;
	int type;
	struct stat stat;
	struct memfs_file *parent;
	union {
		//directory
		struct{
			struct memfs_file ** children;
			unsigned int children_length;
		} dir;
		//regular file
		struct{
			unsigned char * contents;
		} file;
		//link
		struct{
			char * target;
		} link ;
	} extra;
};

struct memfs_state {
	struct memfs_file *root;
};

void memfs_free_file(struct memfs_file *file);

struct memfs_file *find_file(struct memfs_file *root, const char * path){
	//If path starts with '/', and we're not in the root, error out
	if(strncmp(path, "/", 1) == 0){
		if(root->parent != NULL){
			struct memfs_file *new_root = root->parent;
			while(new_root->parent != NULL){
				new_root = new_root->parent;
			}
			return find_file(new_root, path + 1);
		}else{
			return find_file(root, path + 1);
		}
	}
	if(strcmp(path, "") == 0){
		if(root->type == MEMFS_TYPE_DIR){
			return root;
		}
	}
		 
	//see if this is the directory we're looking for
	if(strcmp(path, root->name) == 0){
		return root;
	}
	//otherwise, look through the path until the next /, and compare 
	//  the children for the filenames
	char * path_chunk_end = index(path, '/');
	int path_chunk_len;
	int path_is_in_subdir = 0;
	if(path_chunk_end == NULL){
		path_chunk_len = strlen(path);
		path_is_in_subdir = 0;
	}else{
		path_chunk_len = path_chunk_end - path;
		path_is_in_subdir = 1;
	}
	
	struct memfs_file *cur_child;
	for(int i = 0; i < root->extra.dir.children_length; i++){
		cur_child = *(root->extra.dir.children + i);
		if(strncmp(path, cur_child->name, path_chunk_len) == 0 &&
			 strlen(cur_child->name) == path_chunk_len){
			if(path_is_in_subdir){
				if(cur_child->type == MEMFS_TYPE_DIR){
					return find_file(cur_child, path_chunk_end + 1);
				}else{
					return NULL;
				}
			}else{
				return cur_child;
			}
		}
	}

	return NULL;
}

static struct stat * file_to_stat(const struct memfs_file *file, struct stat *ret){
	memcpy(ret, &file->stat, sizeof(struct stat));

	return ret;
}

static struct stat * new_stat_for_file(const struct memfs_file *file){
	struct stat *ret = malloc(sizeof(stat));
	memset(ret, 0, sizeof(stat));
	return file_to_stat(file, ret);
}

static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
												off_t offset, struct fuse_file_info *fi){
	struct memfs_file *found = find_file(MEMFS_DATA->root, path);
	if(found && found->type == MEMFS_TYPE_DIR){
		filler(buf, ".", &found->stat, 0);
		if(found->parent){
			filler(buf, "..", &found->parent->stat, 0);
		}
		for(int i = 0; i < found->extra.dir.children_length; i++){
			struct memfs_file * cur_child = *(found->extra.dir.children + i);
			filler(buf, cur_child->name, &cur_child->stat, 0);
		}
		return 0;
	}else{
		return -ENOENT;
	}
}

static int memfs_remove_child_from_dir(struct memfs_file *dir, const char *child_name){
	int found_child_idx = -1;
	struct memfs_file *found_child = NULL;
	for(int i = 0; i < dir->extra.dir.children_length; i++){
		found_child = dir->extra.dir.children[i];
		if(strcmp(child_name, found_child->name) == 0){
			found_child_idx = i;
			break;
		}
		found_child = NULL;
	}
	if(found_child_idx == -1){
		return -ENOENT;
	}
	
	int new_size = dir->extra.dir.children_length - 1;
	//move the last child to the current index
	dir->extra.dir.children[found_child_idx] = dir->extra.dir.children[new_size];
	//preserve the old one in case realloc fails
	dir->extra.dir.children[new_size] = found_child;
	//realloc the children array
	void * new_mem = realloc(dir->extra.dir.children, new_size * sizeof(struct memfs_file *));
	if(new_size != 0 && new_mem == NULL){
		return -ENOMEM;
	}
	dir->extra.dir.children = new_mem;
	dir->extra.dir.children_length = new_size;
	//remove parent from child
	found_child->parent = NULL;
	found_child->stat.st_nlink--;
	
	return 0;
}

static int memfs_add_child_to_dir(struct memfs_file *dir, struct memfs_file *child){
	int new_size = dir->extra.dir.children_length + 1;
	void * new_mem = realloc(dir->extra.dir.children, new_size * sizeof(struct memfs_file *));
	if(new_mem == NULL){
		return -ENOMEM;
	}
	dir->extra.dir.children_length = new_size;
	dir->extra.dir.children = new_mem;
	//memcpy(dir->extra.dir.children + (new_size - 1), child, sizeof(struct memfs_file));
	dir->extra.dir.children[new_size - 1] = child;
	child->parent = dir;
	child->stat.st_nlink++;
	
	return 0;
}

static int memfs_getattr(const char *path, struct stat *stbuf){
	int res = 0;
	
	/* stat:
		 st_dev -> device ID
		 st_ino -> inode number
		 st_mode -> protection
		 st_nlink -> number of hard links
		 st_uid, st_gid
		 st_size -> size
		 st_atime/mtime/ctime -> access/mod/change
	*/

	struct memfs_file *found = find_file(MEMFS_DATA->root, path);
	if(found){
		file_to_stat(found, stbuf);
		return 0;
	}else{
		return -ENOENT;
	}
}

struct memfs_file *_memfs_create_entry(const char *name, mode_t mode){
	struct memfs_file *ret = malloc(sizeof(struct memfs_file));
	memset(ret, 0, sizeof(struct memfs_file));
	long name_size = strlen(name);
	ret->name = malloc(name_size + 1);
	memset(ret->name, 0, name_size + 1);
	strncpy(ret->name, name, name_size);
	memcpy(&ret->stat, &mode, sizeof(mode_t));
	
	struct fuse_context * ctx = fuse_get_context();
	ret->stat.st_uid = ctx->uid;
	ret->stat.st_gid = ctx->gid;

	time_t cur_time = time(NULL);
	ret->stat.st_ctime = cur_time;
	ret->stat.st_atime = cur_time;
	ret->stat.st_mtime = cur_time;
	
	return ret;
}

struct memfs_file *memfs_create_dir(const char *name, mode_t mode){
	struct memfs_file *ret;

	ret = _memfs_create_entry(name, mode);
	ret->type = MEMFS_TYPE_DIR;
	ret->stat.st_mode = S_IFDIR | mode;

	return ret;
}

struct memfs_file *memfs_create_file(const char *name, mode_t mode){
	struct memfs_file *ret;

	ret = _memfs_create_entry(name, mode);
	ret->type = MEMFS_TYPE_FILE;
	ret->stat.st_mode = S_IFREG | mode;
	
	return ret;
}

static int memfs_mkdir(const char *path, mode_t mode){
	int path_len = strlen(path);
	char * path_copy = malloc(path_len + 1);
	memset(path_copy, 0, path_len + 1);
	memcpy(path_copy, path, path_len);
	char * last_slash = rindex(path_copy, '/');
	if(last_slash == NULL){
		return -ENOENT;
	}
	struct memfs_file *new_file = memfs_create_dir(last_slash + 1, mode);
	if(last_slash == path){ //if it's being created in root...
		memfs_add_child_to_dir(MEMFS_DATA->root, new_file);
	}else{
		//Take out the last slash, make it end of string so we can find it
		*last_slash = '\0';
		struct memfs_file *found_parent = find_file(MEMFS_DATA->root, path_copy);
		if(found_parent){
			memfs_add_child_to_dir(found_parent, new_file);
		}else{
			memfs_free_file(new_file);
			new_file = 0;
			free(path_copy);
			path_copy = 0;
			return -ENOENT;
		}
	}
	if(path_copy){
		free(path_copy);
		path_copy = 0;
	}
	return 0;
}

void memfs_free_file(struct memfs_file *file){
	if(!file){
		return;
	}
	//dealloc name
	if(file->name){
		printf("Freeing file: %s\n", file->name);
		free(file->name);
		file->name = NULL;
	}
	if(file->type == MEMFS_TYPE_DIR){
		//dealloc children, if folder
		for(int i = 0; i < file->extra.dir.children_length; i++){
			memfs_free_file(*(file->extra.dir.children + i));
		}
		//dealloc children array
		if(file->extra.dir.children){
			free(file->extra.dir.children);
			file->extra.dir.children = 0;
		}
	}else if(file->type == MEMFS_TYPE_FILE){
		//dealloc contents, if file
		if(file->extra.file.contents){
			free(file->extra.file.contents);
			file->extra.file.contents = NULL;
		}
	}
	//deallocate file itself
	free(file);
}
int memfs_create(const char *path, mode_t mode, struct fuse_file_info *info){
	int path_len = strlen(path);
	char * path_copy = malloc(path_len + 1);
	memset(path_copy, 0, path_len + 1);
	memcpy(path_copy, path, path_len);
	char * last_slash = rindex(path_copy, '/');
	if(last_slash == NULL){
		return -ENOENT;
	}
	if(strlen(last_slash) == 0){
		return -EFAULT;
	}
	struct memfs_file *new_file = memfs_create_file(last_slash + 1, mode);
	//adding to root...
	if(last_slash == path){
		memfs_add_child_to_dir(MEMFS_DATA->root, new_file);
	}else{
		*last_slash = '\0';
		struct memfs_file *found_parent = find_file(MEMFS_DATA->root, path_copy);
		if(found_parent){
			memfs_add_child_to_dir(found_parent, new_file);
		}else{
			memfs_free_file(new_file);
			new_file = 0;
			free(path_copy);
			path_copy = 0;
			return -ENOENT;
		}
	}
	if(path_copy){
		free(path_copy);
		path_copy = 0;
	}
	return 0;
}

int memfs_utimens(const char *path, const struct timespec tv[2]){
	const struct timespec access_time = tv[0];
	const struct timespec mod_time = tv[1];
	
	struct memfs_file *found = find_file(MEMFS_DATA->root, path);
	if(found){
		found->stat.st_atime = access_time.tv_sec;
		found->stat.st_mtime = mod_time.tv_sec;
		return 0;
	}else{
		return -ENOENT;
	}
}

int memfs_rename(const char *src, const char *dest){
	int src_len = strlen(src);
	int dest_len = strlen(dest);
	if(src_len == 0 || dest_len == 0){
		return -ENOENT;
	}
	printf("Moving %s to %s\n", src, dest);
	struct memfs_file *src_file = find_file(MEMFS_DATA->root, src);
	if(src_file){
		char * dest_copy = malloc(dest_len + 1);
		memset(dest_copy, 0, dest_len + 1);
		strncpy(dest_copy, dest, dest_len);
		char * last_slash = rindex(dest_copy, '/');
		if(last_slash == NULL){ 
			printf("No last slash!\n");
			free(dest_copy);
			return -ENOENT;
		}

		*last_slash = '\0';
		char * dest_folder = dest_copy;
		char * dest_name = last_slash + 1;
		int dest_name_len = strlen(dest_name);

		if(dest_name_len == 0){
			printf("No destination name!\n");
			free(dest_copy);
			return -ENOENT;
		}
		if(strlen(dest_folder) == 0){
			dest_folder = "/";
		}
		
		struct memfs_file *dest_folder_found = find_file(MEMFS_DATA->root, dest_folder);
		if(dest_folder_found == NULL){
			printf("Unable to find destination folder");
			free(dest_copy);
			return -ENOENT;
		}
		
		int status = 0;
		status = memfs_remove_child_from_dir(src_file->parent, src_file->name);
		if(status != 0){
			printf("Unable to remove child from directory\n");
			free(dest_copy);
			return status;
		}
		status = memfs_add_child_to_dir(dest_folder_found, src_file);
		if(status != 0){
			printf("File info lost/leaked, could remove from old dir, but not add to new in rename\n");
			free(dest_copy);
			return status;
		}
		//update name
		free(src_file->name);
		src_file->name = malloc(dest_name_len + 1);
		if(src_file->name == NULL){
			printf("File messed up, has no name due to failed allocation\n");
			free(dest_copy);
			return -ENOMEM;
		}
		memset(src_file->name, 0, dest_name_len + 1);
		strncpy(src_file->name, dest_name, dest_name_len);
		
		free(dest_copy);
		dest_copy = 0;
		
		return 0;
	}else{
		printf("Unable to find %s\n", src);
		return -ENOENT;
	}
}

int memfs_unlink(const char *file){
	if(strlen(file) == 0) return -ENOENT;
	
	struct memfs_file *found = find_file(MEMFS_DATA->root, file);
	if(found){
		char *file_name = rindex(file, '/') + 1;
		if(strlen(file_name) == 0) return -ENOENT;
		int status = memfs_remove_child_from_dir(found->parent, file_name);
		if(status != 0) return status;
		if(found->stat.st_nlink == 0){
			memfs_free_file(found);
		}
	}else{
		return -ENOENT;
	}
	
	return 0;
}

int memfs_read(const char *file, char * buf, size_t max_size, off_t offset, struct fuse_file_info *info){
	if(strlen(file) == 0) return -ENOENT;

	struct memfs_file *found = find_file(MEMFS_DATA->root, file);
	if(found){
		if(found->type != MEMFS_TYPE_FILE) return -EINVAL;
		memset(buf, 0, max_size);
		int read_size = ((offset + max_size) > found->stat.st_size) ? (found->stat.st_size - offset) : max_size;
		if(read_size < 0) read_size = 0;
		memcpy(buf, found->extra.file.contents + offset, read_size);
		return read_size;
	}else{
		return -ENOENT;
	}
}

int memfs_write(const char *file, const char * buf, size_t size, off_t offset, struct fuse_file_info *info){
	if(strlen(file) == 0) return -ENOENT;

	struct memfs_file *found = find_file(MEMFS_DATA->root, file);
	if(found){
		if(found->type != MEMFS_TYPE_FILE) return -EINVAL;
		if(found->stat.st_size < (size + offset)){
			int new_size = size + offset;
			void * new_mem = realloc(found->extra.file.contents, new_size);
			if(new_mem == 0) return -ENOMEM;
			memset(new_mem + offset, 0, size);
			found->extra.file.contents = new_mem;
			found->stat.st_size = size + offset;
		}
		memcpy(found->extra.file.contents + offset, buf, size);
		return size;
	}else{
		return -ENOENT;
	}
}

int memfs_truncate(const char *file, off_t new_size){
	if(strlen(file) == 0) return -ENOENT;

	struct memfs_file *found = find_file(MEMFS_DATA->root, file);
	if(found){
		if(found->type != MEMFS_TYPE_FILE) return -EINVAL;
		if(found->stat.st_size == new_size){
			return 0;
		}
		void * new_mem = realloc(found->extra.file.contents, new_size);
		if(new_size != 0 && new_mem == NULL){
			return -ENOMEM;
		}
		found->extra.file.contents = new_mem;
		if(new_size > found->stat.st_size){
			int start = found->stat.st_size;
			int size = new_size - start;
			memset(new_mem + start, 0, size);
		}
		found->stat.st_size = new_size;
		return 0;
	}else{
		return -ENOENT;
	}
}

int memfs_rmdir(const char *dir){
	if(strlen(dir) == 0) return -ENOENT;
	
	struct memfs_file *found = find_file(MEMFS_DATA->root, dir);
	if(found){
		if(found->type != MEMFS_TYPE_DIR) return -ENOTDIR;
		if(found->extra.dir.children_length != 0) return -ENOTEMPTY;
		char *dir_name = rindex(dir, '/') + 1;
		if(strlen(dir_name) == 0){
			*(dir_name - 1) = '\0';
			if(strlen(dir_name) == 0){
				return -ENOENT;
			}
		}
		int status = memfs_remove_child_from_dir(found->parent, dir_name);
		if(status != 0) return status;
		if(found->stat.st_nlink == 0){
			memfs_free_file(found);
		}
	}else{
		return -ENOENT;
	}
	
	return 0;
}

void memfs_destroy(){
	printf("Cleaning up filesystem\n");
	memfs_free_file(MEMFS_DATA->root);
	
	free(MEMFS_DATA);
}

void * memfs_init(struct fuse_conn_info *info){
	memfs_mkdir("/foo", 0666);
	memfs_mkdir("/foo/bar", 0456);
	memfs_mkdir("/foo/bar/blargh", 0456);
	memfs_mkdir("/foo/bar/baz", 0777);
	memfs_mkdir("/foo/haha", 0777);
	memfs_mkdir("/foo/haha/boo", 0777);
	
	memfs_create("/foo/tmp-file", 0444, NULL);
	memfs_create("/my-file", 0444, NULL);
	struct memfs_file *found = find_file(MEMFS_DATA->root, "/my-file");
	const char file_contents[] = "I am the very model of a modern major general...\n";
	found->extra.file.contents = malloc(strlen(file_contents));
	memcpy(found->extra.file.contents, file_contents, strlen(file_contents));
	found->stat.st_size = strlen(file_contents);
	
	//We're keeping the same initialization data
	return MEMFS_DATA;
}


static struct fuse_operations memfs_oper = {
	//open/opendir are just checking permissions, default is access
	/*
		.open = memfs_open,
		.flush = memfs_flush,
		.opendir = memfs_opendir,
		.chmod = memfs_chmod,
		.chown = memfs_chown,
	*/
	.truncate = memfs_truncate,
	.write = memfs_write,
	.read = memfs_read,
	.rmdir = memfs_rmdir,
	.unlink = memfs_unlink,
	.rename = memfs_rename,
	.create = memfs_create,
	.readdir = memfs_readdir,
	.mkdir = memfs_mkdir,
	.getattr = memfs_getattr,
	.destroy = memfs_destroy,
	.init = memfs_init,
	.utimens = memfs_utimens,
};


int main(int argc, char **argv){
	struct memfs_state * state = malloc(sizeof(struct memfs_state));
	memset(state, 0, sizeof(struct memfs_state));
	state->root = memfs_create_dir("/", 0777);

	/*
	struct memfs_file *foo_dir = memfs_create_dir("foo", 0666);
	memfs_add_child_to_dir(state->root, foo_dir);
	struct memfs_file *bar_file = memfs_create_file("bar", 0456);
	memfs_add_child_to_dir(state->root, bar_file);
	struct memfs_file *foo_dir_found = find_file(state->root, "/foo");
	struct memfs_file *baz_file = memfs_create_file("baz", 0555);
	memfs_add_child_to_dir(foo_dir_found, baz_file);

	struct memfs_file *found = NULL;
	found = find_file(state->root, "/");
	printf("find file: '/' %p -- %s\n", found, found ? found->name : "[Not Found]");
	found = find_file(state->root, "/foo");
	printf("find file: '/foo' %p -- %s\n", found, found ? found->name : "[Not Found]");
	found = find_file(state->root, "/bar");
	printf("find file: '/bar' %p -- %s\n", found, found ? found->name : "[Not Found]");
	found = find_file(state->root, "/baz");
	printf("find file: '/baz' %p -- %s\n", found, found ? found->name : "[Not Found]");
	found = find_file(state->root, "/foo/baz");
	printf("find file: '/foo/baz' %p -- %s\n", found, found ? found->name : "[Not Found]");
	*/
	return fuse_main(argc, argv, &memfs_oper, state);
}
