/*
*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"
#include "pa4-encfs.h"
#define ENCRYPT 1
#define DECRYPT 0
#define PASSTHROUGH -1

static void encfs_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, ENCFS_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here
}

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX];
	encfs_fullpath(ffrom, from);
	char fto[PATH_MAX];
	encfs_fullpath(fto, to);

	res = symlink(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX];
	encfs_fullpath(ffrom, from);
	char fto[PATH_MAX];
	encfs_fullpath(fto, to);

	res = rename(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX];
	encfs_fullpath(ffrom, from);
	char fto[PATH_MAX];
	encfs_fullpath(fto, to);

	res = link(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	char* ostream_ptr;
	size_t ostream_size;
	FILE* istream;
	FILE* ostream;
	int res;
	(void) fi;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	/* open file and decrypt it */

	istream = fopen(fpath, "rb");
	ostream = open_memstream(&ostream_ptr, &ostream_size);
	do_crypt(istream, ostream, DECRYPT, ENCFS_DATA->keystr);

	/* pass stream on to fread */

	fseeko(ostream, offset, SEEK_SET);
	int csize = sizeof(char);
	res = csize * fread(buf, csize, size, ostream);

	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	char* istream_ptr;
	size_t istream_size;
	char* ostream_ptr;
	size_t ostream_size;
	FILE* istream;
	FILE* ostream;
        int fd;
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	(void) fi;

	/* convert input buffer to stream */

	istream = open_memstream(&istream_ptr, &istream_size);
	fwrite(buf, size, sizeof(char), istream);

        /* encrypt */
        /* read output stream to file */
	ostream = fopen(fpath, "rw+");
	if (!do_crypt(istream, ostream, ENCRYPT, ENCFS_DATA->keystr)) return -1;
	fclose(ostream);

	res = size;

	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

	(void) fi;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	/* create empty encrypted file */

	int res;
	res = creat(fpath, mode);
	if(res == -1)
	return -errno;

	close(res);

	return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create	 = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr	= encfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	struct encfs_data* data;
	data = malloc(sizeof(struct encfs_data));
	if (data == NULL) {
		perror("main calloc");
		abort();
	}

	/* grab the keystr and rootdir and save their values */
	data->rootdir = realpath(argv[argc-2], NULL);
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;
	data->keystr = argv[argc-2];
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;

	umask(0);
	return fuse_main(argc, argv, &encfs_oper, data);
}
