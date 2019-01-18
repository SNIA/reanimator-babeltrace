// Copyright 2019 FSL Stony Brook University

#ifndef FSL_SYSCALL_HANDLERS
#define FSL_SYSCALL_HANDLERS

#include "fsl-pretty.h"

void access_syscall_handler(long *args, void **v_args);
void mmap_syscall_handler(long *args, void **v_args);

#endif
