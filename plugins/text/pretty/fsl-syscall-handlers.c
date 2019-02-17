// Copyright FSL Stony Brook University

#include "fsl-syscall-handlers.h"

extern struct GenericSyscall persistent_syscall;
extern GHashTable *syscalls_kv_store;
extern FILE *buffer_file;
extern uint64_t event_count;

static GHashTable *lookahead_cache = NULL;
static char fakeBuffer[8192];
static void *buffer_ptr = NULL;

#define READ_SYSCALL_ARG(param, key)                                           \
	SyscallArgument *param = NULL;                                         \
	{                                                                      \
		uint64_t local_thread_id = GET_THREAD_ID();                    \
		struct GenericSyscall *thread_local_kv_store =                 \
			(struct GenericSyscall *)g_hash_table_lookup(          \
				syscalls_kv_store, &local_thread_id);          \
		param = (SyscallArgument *)g_hash_table_lookup(                \
			thread_local_kv_store->key_value, key);                \
	}

static long get_value_for_args(SyscallArgument *arg);
static void set_buffer_to_vargs(long *args, void **v_args, uint64_t args_idx,
				uint64_t v_args_idx, char *arg_name);
static void set_buffer_to_vargs_from_cache(long *args, void **v_args,
					   uint64_t args_idx,
					   uint64_t v_args_idx, char *arg_name,
					   char *buffer_ptr);
static void *is_in_lookahead_cache(uint64_t record_id);
static void add_to_lookahead_cache(uint64_t record_id, void *buffer);

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
	uint64_t event_id = 0;
	uint64_t entry_event_count = 0;
	uint64_t data_size = 0;
	uint64_t current_pos = 0;
	void *cached_buffer = NULL;
	void *buffer = NULL;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	cached_buffer = is_in_lookahead_cache(entry_event_count);
	if (cached_buffer) {
		set_buffer_to_vargs_from_cache(args, v_args, 1, 0, "buf",
					       cached_buffer);
		fseek(buffer_file, current_pos, SEEK_SET);
	} else {
		while (event_id != entry_event_count) {
			printf("read system call event ids are not matched %ld %ld\n",
			       event_id, entry_event_count);
			fread(&data_size, sizeof(data_size), 1, buffer_file);
			buffer = malloc(data_size);
			fread(buffer, sizeof(char), data_size, buffer_file);
			add_to_lookahead_cache(event_id, buffer);
			fread(&event_id, sizeof(event_id), 1, buffer_file);
		}
		if (event_id == entry_event_count) {
			set_buffer_to_vargs(args, v_args, 1, 0, "buf");
		} else {
			assert(0);
		}
	}
}

void stat_syscall_handler(long *args, void **v_args)
{
	uint64_t event_id = 0, current_pos = 0;
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(path, "path")
	args[0] = get_value_for_args(path);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	if (event_id == entry_event_count) {
		set_buffer_to_vargs(args, v_args, 1, 0, "buf");
	} else {
		printf("stat system call event ids are not matched %ld %ld\n",
		       event_id, entry_event_count);
		fseek(buffer_file, current_pos, SEEK_SET);
		v_args[0] = &fakeBuffer;
		args[1] = (long)&fakeBuffer;
	}
}

void fstat_syscall_handler(long *args, void **v_args)
{
	uint64_t event_id = 0, current_pos = 0;
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	if (event_id == entry_event_count) {
		set_buffer_to_vargs(args, v_args, 1, 0, "buf");
	} else {
		printf("stat system call event ids are not matched %ld %ld\n",
		       event_id, entry_event_count);
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
	uint64_t event_id = 0, current_pos = 0;
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	if (event_id == entry_event_count) {
		set_buffer_to_vargs(args, v_args, 1, 0, "buf");
	} else {
		printf("write event ids are not matched %ld %ld\n", event_id,
		       entry_event_count);
		fseek(buffer_file, current_pos, SEEK_SET);
		v_args[0] = &fakeBuffer;
		args[1] = (long)&fakeBuffer;
	}
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

static void *is_in_lookahead_cache(uint64_t record_id)
{
	if (lookahead_cache == NULL) {
		lookahead_cache = g_hash_table_new(g_int64_hash, g_int64_equal);
		return NULL;
	}
	return g_hash_table_lookup(lookahead_cache, &record_id);
}

static void add_to_lookahead_cache(uint64_t record_id, void *buffer)
{
	uint64_t *id;
	id = (uint64_t *)malloc(sizeof(uint64_t));
	*id = record_id;

	if (lookahead_cache == NULL) {
		lookahead_cache = g_hash_table_new(g_int64_hash, g_int64_equal);
	}
	g_hash_table_insert(lookahead_cache, id, buffer);
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

static void set_buffer_to_vargs(long *args, void **v_args, uint64_t args_idx,
				uint64_t v_args_idx, char *arg_name)
{
	uint64_t data_size = 0;
	fread(&data_size, sizeof(data_size), 1, buffer_file);
	buffer_ptr = malloc(data_size);
	fread(buffer_ptr, sizeof(char), data_size, buffer_file);
	v_args[v_args_idx] = buffer_ptr;
	args[args_idx] = (long)buffer_ptr;
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Integer;
	argument->data = buffer_ptr;
	uint64_t local_thread_id = GET_THREAD_ID();
	struct GenericSyscall *thread_local_kv_store =
		(struct GenericSyscall *)g_hash_table_lookup(syscalls_kv_store,
							     &local_thread_id);
	g_hash_table_insert(thread_local_kv_store->key_value, arg_name,
			    (gpointer)argument);
}

static void set_buffer_to_vargs_from_cache(long *args, void **v_args,
					   uint64_t args_idx,
					   uint64_t v_args_idx, char *arg_name,
					   char *buffer_ptr)
{
	v_args[v_args_idx] = buffer_ptr;
	args[args_idx] = (long)buffer_ptr;
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Integer;
	argument->data = buffer_ptr;
	uint64_t local_thread_id = GET_THREAD_ID();
	struct GenericSyscall *thread_local_kv_store =
		(struct GenericSyscall *)g_hash_table_lookup(syscalls_kv_store,
							     &local_thread_id);
	g_hash_table_insert(thread_local_kv_store->key_value, arg_name,
			    (gpointer)argument);
}
