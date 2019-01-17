// Copyright FSL Stony Brook University

#include <babeltrace/babeltrace.h>
#include <babeltrace/bitfield-internal.h>
#include <babeltrace/common-internal.h>
#include <babeltrace/compat/time-internal.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "fsl-pretty.h"

#define CLEANUP_SYSCALL(name)                                                  \
	free(name);                                                            \
	for (int stringIdx = 0; stringIdx < string_fields_cnt; stringIdx++) {  \
		free(string_fields[stringIdx]);                                \
	}                                                                      \
	key_cnt = val_cnt = string_fields_cnt = 0;                             \
	g_hash_table_remove_all(persistent_syscall.key_value);

#define SET_COMMON_FIELDS(ds_field_, key_)                                     \
	if (g_hash_table_lookup(persistent_syscall.key_value, key_)) {         \
		SyscallArgument *result =                                      \
			(SyscallArgument *)g_hash_table_lookup(                \
				persistent_syscall.key_value, key_);           \
		common_fields[ds_field_] = result->data;                       \
	}

extern DataSeriesOutputModule *ds_module;

struct GenericSyscall persistent_syscall = {0};

static uint64_t key_cnt = 0, val_cnt = 0;
static uint64_t backup_key_cnt = 0, backup_val_cnt = 0;
static char key[PARAMETER_COUNT][KEY_LENGTH];
static uint64_t value[PARAMETER_COUNT];
static char backup_key[PARAMETER_COUNT][KEY_LENGTH];
static uint64_t backup_value[PARAMETER_COUNT];

static uint64_t string_fields_cnt = 0;
static char *string_fields[PARAMETER_COUNT];

static char fakeBuffer[8192];

static SyscallEvent syscall_event_type(char *event_name);
static void backup_entry_params();
static void key_destruction(gpointer key);
static void value_destruction(gpointer ptr);
static gpointer copy_syscall_argument(gpointer ptr);
static void insert_value_to_hash_table(char *key_, void *value_);

#ifdef FSL_PRETTY_VERBOSE
static void print_keys_dbg();
#endif

__attribute__((always_inline)) inline void
get_timestamp(struct bt_clock_value *clock_value)
{
	uint64_t timestamp = 0;
	bt_clock_value_get_value(clock_value, &timestamp);
	strcpy(key[key_cnt++], "Timestamp");
	value[val_cnt++] = timestamp;
	// Test
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	argument->type = Integer;
	argument->data = malloc(sizeof(uint64_t));
	*((uint64_t *)argument->data) = timestamp;
	insert_value_to_hash_table("timestamp", (gpointer)argument);
}

__attribute__((always_inline)) inline void
get_syscall_name(const char *syscall_name_full)
{
	char *syscall_name_buffer = malloc(strlen(syscall_name_full) + 1);
	strcpy(key[key_cnt++], "syscall_name_full");
	strcpy(syscall_name_buffer, syscall_name_full);
	value[val_cnt++] = (uint64_t)syscall_name_buffer;
	// Test
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
	strcpy(key[key_cnt++], key_);
	value[val_cnt++] = value_;
	// Test
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
	strcpy(key[key_cnt++], key_);
	value[val_cnt++] = (uint64_t)value_;
	// Test
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
	char *string_field = malloc(strlen(value_) + 1);
	strcpy(key[key_cnt++], key_);
	strcpy(string_field, value_);
	string_fields[string_fields_cnt++] = string_field;
	value[val_cnt++] = (uint64_t)&string_field[0];
	// Test
	char *key_iter = malloc(strlen(key_) + 1);
	strcpy(key_iter, key_);
	SyscallArgument *argument = malloc(sizeof(SyscallArgument));
	char *string_arg = malloc(strlen(value_) + 1);
	argument->type = String;
	strcpy(string_arg, value_);
	argument->data = string_arg;
	insert_value_to_hash_table(key_iter, (gpointer)argument);
}

void print_key_value()
{
	char *syscall_name_full = NULL, *syscall_name = NULL;
	int errnoVal = 0;
	SyscallEvent event_type = unknown_event;
	void *common_fields[DS_NUM_COMMON_FIELDS];
	long int entry_args[10];
	void *v_args[DS_MAX_ARGS];
	GHashTableIter iter;

	syscall_name_full = (char *)value[1];
	event_type = syscall_event_type(syscall_name_full);

	switch (event_type) {
	case compat_event: {
		CLEANUP_SYSCALL(syscall_name_full)
		return;
	}
	case entry_event: {
		// Backup the key array and value array
		// they will be overwritten during syscall exit
		backup_entry_params();
		// print_keys_dbg();
		// Test
		gpointer timestamp = g_hash_table_lookup(
			persistent_syscall.key_value, "timestamp");
		if (timestamp != NULL) {
			insert_value_to_hash_table(
				"entry_timestamp",
				copy_syscall_argument(timestamp));
			g_hash_table_remove(persistent_syscall.key_value,
					    "timestamp");
		}

		key_cnt = val_cnt = 0;
		free(syscall_name_full);
		return;
	}
	case exit_event: {
		// create user arguents
		// print_keys_dbg();
		// Test
		gpointer timestamp = g_hash_table_lookup(
			persistent_syscall.key_value, "timestamp");
		if (timestamp != NULL) {
			insert_value_to_hash_table(
				"exit_timestamp",
				copy_syscall_argument(timestamp));
			g_hash_table_remove(persistent_syscall.key_value,
					    "timestamp");
		}

		int itEntryArg = 0;
		for (int itBck = 4; itBck < backup_val_cnt;
		     ++itBck, ++itEntryArg) {
			entry_args[itEntryArg] = backup_value[itBck];
		}
		for (int itVal = 5; itVal < val_cnt; ++itVal, ++itEntryArg) {
			entry_args[itEntryArg] = value[itVal];
		}
		syscall_name = &syscall_name_full[strlen("syscall_exit_")];
		break;
	}
	default:
		break;
	}

	// Test
	g_hash_table_iter_init(&iter, persistent_syscall.key_value);

	gpointer key_test, value_test;
	while (g_hash_table_iter_next(&iter, &key_test, &value_test)) {
		printf("{ key = %s, value = ", (char *)key_test);
		SyscallArgument *argument = (SyscallArgument *)value_test;
		switch (argument->type) {
		case Integer: {
			printf("%ld }\n", *(uint64_t *)argument->data);
			break;
		}
		case String: {
			printf("\"%s\" }\n", (char *)argument->data);
			break;
		}
		case Double: {
			printf("%f }\n", *(double *)argument->data);
			break;
		}
		default:
			break;
		}
	}

	////////////////////////////////////////////////////////
	if (strcmp(syscall_name, "sendto") == 0
	    || strcmp(syscall_name, "recvfrom") == 0
	    || strcmp(syscall_name, "sendmsg") == 0
	    || strcmp(syscall_name, "recvmsg") == 0
	    || strcmp(syscall_name, "connect") == 0
	    || strcmp(syscall_name, "bind") == 0
	    || strcmp(syscall_name, "getrlimit") == 0
	    || strcmp(syscall_name, "execve") == 0
	    || strcmp(syscall_name, "unknown") == 0
	    || strcmp(syscall_name, "getdents") == 0
	    || strcmp(syscall_name, "readlink") == 0
	    || strcmp(syscall_name, "wait4") == 0) {
		CLEANUP_SYSCALL(syscall_name_full)
		return;
	}
	////////////////////////////////////////////////////////

	SET_COMMON_FIELDS(DS_COMMON_FIELD_TIME_CALLED, "entry_timestamp")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_TIME_RETURNED, "exit_timestamp")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_RETURN_VALUE, "ret")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_EXECUTING_PID, "tid")
	SET_COMMON_FIELDS(DS_COMMON_FIELD_EXECUTING_TID, "tid")
	common_fields[DS_COMMON_FIELD_ERRNO_NUMBER] = &errnoVal;

	if (strcmp(syscall_name, "write") == 0) {
		v_args[0] = &fakeBuffer;
	} else if (strcmp(syscall_name, "read") == 0) {
		v_args[0] = &fakeBuffer;
		uint64_t swap = entry_args[1];
		entry_args[1] = entry_args[2];
		entry_args[2] = swap;
		if (value[4] == 0)
			value[4] = swap;
	} else if (strcmp(syscall_name, "clone") == 0) {
		v_args[0] = &value[3];
		v_args[1] = &value[4];
	} else if (strcmp(syscall_name, "open") == 0
		   || strcmp(syscall_name, "access") == 0
		   || strcmp(syscall_name, "stat") == 0
		   || strcmp(syscall_name, "statfs") == 0) {
		v_args[0] = &backup_value[4];
	} else {
		v_args[0] = NULL;
	}

	printf(" %s entry time %ld exit time %ld retVal %ld tid %ld\n",
	       syscall_name, backup_value[0], value[0], value[4], value[3]);

	bt_common_write_record(ds_module, syscall_name, entry_args,
			       common_fields, v_args);

	CLEANUP_SYSCALL(syscall_name_full)
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
	}
	g_hash_table_insert(persistent_syscall.key_value, key_, value_);
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

__attribute__((always_inline)) inline static void backup_entry_params()
{
	backup_key_cnt = key_cnt;
	backup_val_cnt = val_cnt;

	for (int parameterIdx = 0; parameterIdx < PARAMETER_COUNT;
	     ++parameterIdx) {
		strncpy((char *)&backup_key[0], (const char *)&key[0],
			KEY_LENGTH);
		backup_value[parameterIdx] = value[parameterIdx];
	}
}

#ifdef FSL_PRETTY_VERBOSE
static void print_keys_dbg()
{
	printf("--------------------------------------------------------\n");
	for (int i = 0; i < key_cnt; ++i) {
		printf("{ key : %s , value : %ld }\n", key[i], value[i]);
	}
	printf("--------------------------------------------------------\n");
}
#endif
