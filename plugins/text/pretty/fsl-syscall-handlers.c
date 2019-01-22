// Copyright FSL Stony Brook University

#include "fsl-syscall-handlers.h"

extern struct GenericSyscall persistent_syscall;
extern FILE *buffer_file;
extern uint64_t event_count;
static char fakeBuffer[8192];
void *buffer_ptr = NULL;

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

void open_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(file_name, "filename")
	READ_SYSCALL_ARG(flags, "flags")
	READ_SYSCALL_ARG(mode, "mode")
	args[0] = get_value_for_args(file_name);
	args[1] = get_value_for_args(flags);
	args[2] = get_value_for_args(mode);
	v_args[0] = file_name->data;
}

void close_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);
}

void read_syscall_handler(long *args, void **v_args)
{
	uint64_t event_id = 0, data_size = 0;
	uint64_t current_pos = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	if (event_id == event_count) {
		fread(&data_size, sizeof(data_size), 1, buffer_file);
		buffer_ptr = malloc(data_size);
		fread(buffer_ptr, sizeof(char), data_size, buffer_file);
		v_args[0] = buffer_ptr;
		args[1] = (long)buffer_ptr;
		SyscallArgument *argument = malloc(sizeof(SyscallArgument));
		argument->type = Integer;
		argument->data = buffer_ptr;
		g_hash_table_insert(persistent_syscall.key_value, "buf",
				    (gpointer)argument);
	} else {
		printf("event ids are not matched %ld %ld\n", event_id,
		       event_count);
		fseek(buffer_file, current_pos, SEEK_SET);
		v_args[0] = &fakeBuffer;
		args[1] = (long)&fakeBuffer;
	}
}

void munmap_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(addr, "addr")
	READ_SYSCALL_ARG(len, "len")
	args[0] = get_value_for_args(addr);
	args[1] = get_value_for_args(len);
}

void write_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);
	v_args[0] = &fakeBuffer;
	args[1] = (long)&fakeBuffer;
}

void lseek_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(offset, "offset")
	READ_SYSCALL_ARG(whence, "whence")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(offset);
	args[2] = get_value_for_args(whence);
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
