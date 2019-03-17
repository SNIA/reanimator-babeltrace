// Copyright 2019 FSL Stony Brook University

#ifndef FSL_SYSCALL_HANDLERS
#define FSL_SYSCALL_HANDLERS

#include "fsl-pretty.h"

void access_syscall_handler(long *args, void **v_args);
void mmap_syscall_handler(long *args, void **v_args);
void open_syscall_handler(long *args, void **v_args);
void close_syscall_handler(long *args, void **v_args);
void read_syscall_handler(long *args, void **v_args);
void munmap_syscall_handler(long *args, void **v_args);
void write_syscall_handler(long *args, void **v_args);
void lseek_syscall_handler(long *args, void **v_args);
void fstat_syscall_handler(long *args, void **v_args);
void newfstat_syscall_handler(long *args, void **v_args);
void stat_syscall_handler(long *args, void **v_args);
void clone_syscall_handler(long *args, void **v_args);
void truncate_syscall_handler(long *args, void **v_args);
void ftruncate_syscall_handler(long *args, void **v_args);
void link_syscall_handler(long *args, void **v_args);
void linkat_syscall_handler(long *args, void **v_args);
void unlink_syscall_handler(long *args, void **v_args);
void flock_syscall_handler(long *args, void **v_args);
void mkdir_syscall_handler(long *args, void **v_args);
void openat_syscall_handler(long *args, void **v_args);
void rename_syscall_handler(long *args, void **v_args);
void rmdir_syscall_handler(long *args, void **v_args);
void exit_syscall_handler(long *args, void **v_args);
void fchmodat_syscall_handler(long *args, void **v_args);
void statfs_syscall_handler(long *args, void **v_args);
void fstatfs_syscall_handler(long *args, void **v_args);
void lstat_syscall_handler(long *args, void **v_args);
void newlstat_syscall_handler(long *args, void **v_args);
void fstatat_syscall_handler(long *args, void **v_args);
void newfstatat_syscall_handler(long *args, void **v_args);
void chown_syscall_handler(long *args, void **v_args);
void readlink_syscall_handler(long *args, void **v_args);
void fsync_syscall_handler(long *args, void **v_args);
void fdatasync_syscall_handler(long *args, void **v_args);
void fallocate_syscall_handler(long *args, void **v_args);
void readahead_syscall_handler(long *args, void **v_args);
void pread_syscall_handler(long *args, void **v_args);
void pwrite_syscall_handler(long *args, void **v_args);
void chdir_syscall_handler(long *args, void **v_args);
void mkdirat_syscall_handler(long *args, void **v_args);
void symlink_syscall_handler(long *args, void **v_args);
void creat_syscall_handler(long *args, void **v_args);
void faccessat_syscall_handler(long *args, void **v_args);
void chmod_syscall_handler(long *args, void **v_args);
void umask_syscall_handler(long *args, void **v_args);
void fchmod_syscall_handler(long *args, void **v_args);
void symlinkat_syscall_handler(long *args, void **v_args);
void unlinkat_syscall_handler(long *args, void **v_args);
void utime_syscall_handler(long *args, void **v_args);
void utimensat_syscall_handler(long *args, void **v_args);
void mknod_syscall_handler(long *args, void **v_args);
void mknodat_syscall_handler(long *args, void **v_args);
void pipe_syscall_handler(long *args, void **v_args);
void dup_syscall_handler(long *args, void **v_args);
void dup2_syscall_handler(long *args, void **v_args);
void fcntl_syscall_handler(long *args, void **v_args);
void getdents_syscall_handler(long *args, void **v_args);
void vfork_syscall_handler(long *args, void **v_args);
void set_get_rlimit_syscall_handler(long *args, void **v_args);
void setsid_syscall_handler(long *args, void **v_args);
void setpgid_syscall_handler(long *args, void **v_args);
void getpid_syscall_handler(long *args, void **v_args);
void geteuid_syscall_handler(long *args, void **v_args);
void newstat_syscall_handler(long *args, void **v_args);
void ioctl_syscall_handler(long *args, void **v_args);
void newstat_syscall_handler(long *args, void **v_args);
void listxattr_syscall_handler(long *args, void **v_args);
void llistxattr_syscall_handler(long *args, void **v_args);
void flistxattr_syscall_handler(long *args, void **v_args);
void removexattr_syscall_handler(long *args, void **v_args);
void lremovexattr_syscall_handler(long *args, void **v_args);
void fremovexattr_syscall_handler(long *args, void **v_args);
void lsetxattr_syscall_handler(long *args, void **v_args);
void setxattr_syscall_handler(long *args, void **v_args);
void fsetxattr_syscall_handler(long *args, void **v_args);
void lgetxattr_syscall_handler(long *args, void **v_args);
void getxattr_syscall_handler(long *args, void **v_args);
void fgetxattr_syscall_handler(long *args, void **v_args);
void socket_syscall_handler(long *args, void **v_args);
void bind_syscall_handler(long *args, void **v_args);
void listen_syscall_handler(long *args, void **v_args);
void accept_syscall_handler(long *args, void **v_args);
void connect_syscall_handler(long *args, void **v_args);
void setsockopt_syscall_handler(long *args, void **v_args);
void getsockopt_syscall_handler(long *args, void **v_args);

#endif
