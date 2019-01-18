// Copyright FSL Stony Brook University

#include "fsl-syscall-handlers.h"

extern struct GenericSyscall persistent_syscall;

#define READ_SYSCALL_ARG(param, key)                                           \
	SyscallArgument *param = (SyscallArgument *)g_hash_table_lookup(       \
		persistent_syscall.key_value, key);

static long get_value_for_args(SyscallArgument *arg);

void access_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(file_name, "filename")
	READ_SYSCALL_ARG(mode, "mode")
	args[0] = get_value_for_args(file_name);
	args[1] = get_value_for_args(mode);
	v_args[0] = file_name->data;
}

void mmap_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(addr, "addr")
	READ_SYSCALL_ARG(len, "len")
	READ_SYSCALL_ARG(prot, "prot")
	READ_SYSCALL_ARG(flags, "flags")
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(offset, "offset")
	args[0] = get_value_for_args(addr);
	args[1] = get_value_for_args(len);
	args[2] = get_value_for_args(prot);
	args[3] = get_value_for_args(flags);
	args[4] = get_value_for_args(fd);
	args[5] = get_value_for_args(offset);
}

static long get_value_for_args(SyscallArgument *arg)
{
	switch (arg->type) {
	case String: {
		return (long)arg->data;
	}
	case Integer: {
		return (long)(*(uint64_t *)arg->data);
	}
	case Double: {
		return (long)(*(double *)arg->data);
	}
	default:
		assert(0);
	}
}
