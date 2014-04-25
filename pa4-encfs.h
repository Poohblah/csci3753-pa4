#ifndef _ENCFS_H_
#define _ENCFS_H_
struct encfs_data {
    char* rootdir;
};
#define ENCFS_DATA ((struct encfs_data *) fuse_get_context()->private_data)
#endif
