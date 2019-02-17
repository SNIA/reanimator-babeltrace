// Copyright FSL Stony Brook University

#include <babeltrace/babeltrace.h>
#include <babeltrace/bitfield-internal.h>
#include <babeltrace/common-internal.h>
#include <babeltrace/compat/time-internal.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "fsl-pretty.h"
#include "fsl-syscall-handlers.h"

#define CLEANUP_SYSCALL() g_hash_table_remove_all(persistent_syscall.key_value);

#define CLEANUP_THREAD_LOCAL_SYSCALL()                                         \
	{                                                                      \
		uint64_t local_thread_id = GET_THREAD_ID();                    \
		struct GenericSyscall *thread_local_kv_store =                 \
			(struct GenericSyscall *)g_hash_table_lookup(          \
				syscalls_kv_store, &local_thread_id);          \
		g_hash_table_remove_all(thread_local_kv_store->key_value);     \
	}

#define SET_COMMON_FIELDS(ds_field_, key_)                                     \
	{                                                                      \
		uint64_t local_thread_id = GET_THREAD_ID();                    \
		struct GenericSyscall *thread_local_kv_store =                 \
			(struct GenericSyscall *)g_hash_table_lookup(          \
				syscalls_kv_store, &local_thread_id);          \
		if (g_hash_table_lookup(thread_local_kv_store->key_value,      \
					key_)) {                               \
			SyscallArgument *result =                              \
				(SyscallArgument *)g_hash_table_lookup(        \
					thread_local_kv_store->key_value,      \
					key_);                                 \
			common_fields[ds_field_] = result->data;               \
		}                                                              \
	}

#define ADD_SYSCALL_HANDLER(name, func_ptr)                                    \
	g_hash_table_insert(syscall_handler_map, name, func_ptr);

extern DataSeriesOutputModule *ds_module;

static uint64_t threads_idx = 0;
static uint64_t thread_ids[1024];
static GHashTable *syscall_handler_map = NULL;

struct GenericSyscall persistent_syscall = {0};
GHashTable *syscalls_kv_store = NULL;
FILE *buffer_file = NULL;

static bool isUmaskInitialized = false;

static SyscallEvent syscall_event_type(char *event_name);
static void key_destruction(gpointer key);
static void value_destruction(gpointer ptr);
static gpointer copy_syscall_argument(gpointer ptr);
static void insert_value_to_hash_table(char *key_, void *value_);
static bool contains_thread(uint64_t thread_id);
static void copy_syscall(gpointer key, gpointer value, gpointer kv_store);

#ifdef FSL_PRETTY_VERBOSE
static void print_syscall_arguments();
#endif

static void init_system_call_handlers()
{
	syscall_handler_map =
		g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	ADD_SYSCALL_HANDLER("access", &access_syscall_handler)
	ADD_SYSCALL_HANDLER("mmap", &mmap_syscall_handler)
	ADD_SYSCALL_HANDLER("open", &open_syscall_handler)
	ADD_SYSCALL_HANDLER("close", &close_syscall_handler)
	ADD_SYSCALL_HANDLER("read", &read_syscall_handler)
	ADD_SYSCALL_HANDLER("munmap", &munmap_syscall_handler)
	ADD_SYSCALL_HANDLER("write", &write_syscall_handler)
	ADD_SYSCALL_HANDLER("lseek", &lseek_syscall_handler)
	ADD_SYSCALL_HANDLER("newfstat", &fstat_syscall_handler)
	ADD_SYSCALL_HANDLER("stat", &stat_syscall_handler)
	buffer_file = fopen(bt_common_get_buffer_file_path(), "rb");
}

__attribute__((always_inline)) inline void
get_timestamp(struct bt_clock_value *clock_value)
{
	uint64_t timestamp = 0;
	bt_clock_value_get_value(clock_value, &timestamp);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Integer;
	argument->data = malloc(sizeof(uint64_t));
	*((uint64_t *)argument->data) = timestamp;
	insert_value_to_hash_table("timestamp", (gpointer)argument);
}

__attribute__((always_inline)) inline void
get_syscall_name(const char *syscall_name_full)
{
	char *syscall_name_arg = malloc(strlen(syscall_name_full) + 1);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = String;
	strcpy(syscall_name_arg, syscall_name_full);
	argument->data = syscall_name_arg;
	insert_value_to_hash_table("syscall_name", (gpointer)argument);
}

__attribute__((always_inline)) inline void get_integer_field(char *key_,
							     uint64_t value_)
{
	char *key_iter = malloc(strlen(key_) + 1);
	strcpy(key_iter, key_);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Integer;
	argument->data = malloc(sizeof(uint64_t));
	*((uint64_t *)argument->data) = value_;
	insert_value_to_hash_table(key_iter, (gpointer)argument);
}

__attribute__((always_inline)) inline void get_double_field(char *key_,
							    double value_)
{
	char *key_iter = malloc(strlen(key_) + 1);
	strcpy(key_iter, key_);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Double;
	argument->data = malloc(sizeof(double));
	*((uint64_t *)argument->data) = value_;
	insert_value_to_hash_table(key_iter, (gpointer)argument);
}

__attribute__((always_inline)) inline void get_string_field(char *key_,
							    const char *value_)
{
	char *key_iter = malloc(strlen(key_) + 1);
	strcpy(key_iter, key_);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	char *string_arg = malloc(strlen(value_) + 1);
	argument->type = String;
	strcpy(string_arg, value_);
	argument->data = string_arg;
	insert_value_to_hash_table(key_iter, (gpointer)argument);
}

void fsl_dump_values()
{
	char *syscall_name = NULL;
	int errnoVal = 0;
	SyscallEvent event_type = unknown_event;
	void *common_fields[DS_NUM_COMMON_FIELDS];
	long args[10] = {0};
	void *v_args[DS_MAX_ARGS] = {0};
	char *syscall_name_full = GET_SYSCALL_NAME();
	uint64_t thread_id = GET_THREAD_ID();
	uint64_t process_id = GET_PROCESS_ID();
	struct GenericSyscall *thread_kv_store;

	if (!bt_common_is_fsl_ds_enabled()) {
		return;
	}

	event_type = syscall_event_type(syscall_name_full);
	if (!contains_thread(thread_id)) {
		thread_ids[threads_idx] = thread_id;
		struct GenericSyscall *new_thread_syscall_kv =
			malloc(sizeof(struct GenericSyscall));
		new_thread_syscall_kv->key_value = g_hash_table_new_full(
			g_str_hash, g_str_equal, key_destruction,
			value_destruction);
		g_hash_table_insert(syscalls_kv_store, &thread_ids[threads_idx],
				    new_thread_syscall_kv);
		threads_idx++;
	}
	thread_kv_store = (struct GenericSyscall *)g_hash_table_lookup(
		syscalls_kv_store, &thread_id);

	switch (event_type) {
	case compat_event: {
		CLEANUP_THREAD_LOCAL_SYSCALL()
		CLEANUP_SYSCALL()
		return;
	}
	case entry_event: {
		gpointer timestamp = g_hash_table_lookup(
			persistent_syscall.key_value, "timestamp");
		if (timestamp != NULL) {
			insert_value_to_hash_table(
				"entry_timestamp",
				copy_syscall_argument(timestamp));
			g_hash_table_remove(persistent_syscall.key_value,
					    "timestamp");
		}

		gpointer record_id = g_hash_table_lookup(
			persistent_syscall.key_value, "fsl_record_id");
		if (record_id != NULL) {
			insert_value_to_hash_table(
				"record_id",
				copy_syscall_argument(record_id));
			g_hash_table_remove(persistent_syscall.key_value,
					    "fsl_record_id");
		}

		g_hash_table_foreach(persistent_syscall.key_value,
				     &copy_syscall, thread_kv_store);
		CLEANUP_SYSCALL()
		return;
	}
	case exit_event: {
		gpointer timestamp = g_hash_table_lookup(
			persistent_syscall.key_value, "timestamp");
		if (timestamp != NULL) {
			insert_value_to_hash_table(
				"exit_timestamp",
				copy_syscall_argument(timestamp));
			g_hash_table_remove(persistent_syscall.key_value,
					    "timestamp");
		}

		g_hash_table_foreach(persistent_syscall.key_value,
				     &copy_syscall, thread_kv_store);

		syscall_name = &syscall_name_full[strlen("syscall_exit_")];
		break;
	}
	default:
		break;
	}
#ifdef FSL_PRETTY_VERBOSE
	print_syscall_arguments();
#endif

	// TODO(Umit) finish all these call implementations
	// TODO(Umit) look at unknown syscalls
	if (strcmp(syscall_name, "execve") == 0
	    || strcmp(syscall_name, "wait4") == 0
	    || strcmp(syscall_name, "rt_sigaction") == 0
	    || strcmp(syscall_name, "rt_sigprocmask") == 0
	    || strcmp(syscall_name, "brk") == 0
	    || strcmp(syscall_name, "mprotect") == 0
	    || strcmp(syscall_name, "unknown") == 0
	    || strcmp(syscall_name, "set_tid_address") == 0
	    || strcmp(syscall_name, "set_robust_list") == 0
	    || strcmp(syscall_name, "getrlimit") == 0
	    || strcmp(syscall_name, "clone") == 0
	    || strcmp(syscall_name, "futex") == 0
	    || strcmp(syscall_name, "madvise") == 0) {
		if (strcmp(syscall_name, "wait4") == 0 && !isUmaskInitialized) {
			isUmaskInitialized = true;
			ds_write_umask_at_start(ds_module, process_id);
		}
		CLEANUP_THREAD_LOCAL_SYSCALL()
		CLEANUP_SYSCALL()
		return;
	}

	SET_COMMON_FIELDS(DS_COMMON_FIELD_TIME_CALLED, "entry_timestamp")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_TIME_RETURNED, "exit_timestamp")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_RETURN_VALUE, "ret")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_EXECUTING_PID, "pid")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_EXECUTING_TID, "tid")
	common_fields[DS_COMMON_FIELD_ERRNO_NUMBER] = &errnoVal;

	syscall_handler handler =
		g_hash_table_lookup(syscall_handler_map, syscall_name);

	if (handler == NULL) {
		printf("%s handler has not implemented yet !!!\n",
		       syscall_name);
		assert(0);
	}
	handler(args, &(v_args[0]));

	bt_common_write_record(ds_module, syscall_name, args, common_fields,
			       v_args);

	CLEANUP_THREAD_LOCAL_SYSCALL()
	CLEANUP_SYSCALL()
	return;
}

static gpointer copy_syscall_argument(gpointer value)
{
	SyscallArgument *new_arg = NULL;
	SyscallArgument *arg = (SyscallArgument *)value;
	switch (arg->type) {
	case Integer: {
		new_arg = malloc(sizeof(SyscallArgument));
		new_arg->type = Integer;
		new_arg->data = malloc(sizeof(uint64_t));
		*(uint64_t *)(new_arg->data) = *(uint64_t *)arg->data;
		break;
	}
	case Double: {
		new_arg = malloc(sizeof(SyscallArgument));
		new_arg->type = Double;
		new_arg->data = malloc(sizeof(double));
		*(double *)(new_arg->data) = *(double *)arg->data;
		break;
	}
	case String: {
		new_arg = malloc(sizeof(SyscallArgument));
		new_arg->type = String;
		new_arg->data = malloc(strlen((char *)arg->data) + 1);
		strcpy((char *)new_arg->data, (char *)arg->data);
		break;
	}
	default:
		assert(0);
	}
	return new_arg;
}

static void key_destruction(gpointer key_)
{
	if (strcmp(key_, "syscall_name") || strcmp(key_, "timestamp")) {
		return;
	}
	free(key_);
}

static void value_destruction(gpointer ptr)
{
	SyscallArgument *arg = (SyscallArgument *)ptr;
	free(arg->data);
	free(arg);
}

static void insert_value_to_hash_table(char *key_, void *value_)
{
	if (persistent_syscall.key_value == NULL) {
		persistent_syscall.key_value = g_hash_table_new_full(
			g_str_hash, g_str_equal, key_destruction,
			value_destruction);
		syscalls_kv_store =
			g_hash_table_new(g_int64_hash, g_int64_equal);
		init_system_call_handlers();
	}
	g_hash_table_insert(persistent_syscall.key_value, key_, value_);
}

__attribute__((always_inline)) inline static bool
contains_thread(uint64_t thread_id)
{
	for (int i = 0; i < threads_idx; i++) {
		if (thread_id == thread_ids[i]) {
			return true;
		}
	}
	return false;
}

__attribute__((always_inline)) inline static void
copy_syscall(gpointer key, gpointer value, gpointer kv_store)
{
	SyscallArgument *arg_value = (SyscallArgument *)value;
	SyscallArgument *copy_argument = malloc(sizeof(SyscallArgument));
	switch (arg_value->type) {
	case Integer: {
		copy_argument->data = malloc(sizeof(uint64_t));
		memcpy(copy_argument->data, arg_value->data, sizeof(uint64_t));
		copy_argument->type = arg_value->type;
		break;
	}
	case Double: {
		copy_argument->data = malloc(sizeof(double));
		memcpy(copy_argument->data, arg_value->data, sizeof(double));
		copy_argument->type = arg_value->type;
		break;
	}
	case String: {
		char *str_value = (char *)arg_value->data;
		copy_argument->data = malloc(strlen(str_value) + 1);
		memcpy(copy_argument->data, arg_value->data,
		       strlen(str_value) + 1);
		copy_argument->type = arg_value->type;
		break;
	}
	default:
		break;
	}

	GHashTable *key_value_store =
		((struct GenericSyscall *)kv_store)->key_value;
	g_hash_table_insert(key_value_store, key, copy_argument);
}

__attribute__((always_inline)) inline static SyscallEvent
syscall_event_type(char *event_name)
{
	if (strstr(event_name, "compat")) {
		return compat_event;
	}

	if (strstr(event_name, "syscall_entry")) {
		return entry_event;
	}

	if (strstr(event_name, "syscall_exit")) {
		return exit_event;
	}

	printf("%s\n", event_name);
	assert(0);
}

#ifdef FSL_PRETTY_VERBOSE
__attribute__((always_inline)) inline static void print_syscall_arguments()
{
	GHashTableIter iter;
	gpointer key_test, value_test;
	uint64_t thread_id = GET_THREAD_ID();
	struct GenericSyscall *thread_kv_store =
		(struct GenericSyscall *)g_hash_table_lookup(syscalls_kv_store,
							     &thread_id);

	g_hash_table_iter_init(&iter, thread_kv_store->key_value);

	printf("-------------------------------------------------------------\n");
	while (g_hash_table_iter_next(&iter, &key_test, &value_test)) {
		printf("{ key = %s, value = ", (char *)key_test);
		SyscallArgument *argument = (SyscallArgument *)value_test;
		switch (argument->type) {
		case Integer: {
			printf("%ld type = Integer }\n",
			       *(uint64_t *)argument->data);
			break;
		}
		case String: {
			printf("\"%s\" type = String }\n",
			       (char *)argument->data);
			break;
		}
		case Double: {
			printf("%f type = Double }\n",
			       *(double *)argument->data);
			break;
		}
		default:
			printf("%ld type = Unknown }\n",
			       *(uint64_t *)argument->data);
			break;
		}
	}
	printf("-------------------------------------------------------------\n");
}
#endif
