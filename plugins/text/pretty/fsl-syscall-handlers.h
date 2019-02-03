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
void stat_syscall_handler(long *args, void **v_args);

#endif
