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


#endif
