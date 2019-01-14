// Copyright FSL Stony Brook University

#include <babeltrace/babeltrace.h>
#include <babeltrace/bitfield-internal.h>
#include <babeltrace/common-internal.h>
#include <babeltrace/compat/time-internal.h>
#include <stdio.h>
#include <string.h>
#include "fsl-pretty.h"

/* Array to store key of a filed in trace event record */
char key[100][40];
uint64_t key_cnt = 0;
/* Array to store value of a field in trace event record */
uint64_t value[100];
uint64_t val_cnt = 0;

/* Backup Array to store key of a filed in trace event record */
char backup_key[100][40];
uint64_t backup_key_cnt;
/* Array to store value of a field in trace event record */
uint64_t backup_value[100];
uint64_t backup_val_cnt;

void *common_fields[DS_NUM_COMMON_FIELDS];
char sys_name[200];
long int entry_args[10];
void *v_args[DS_MAX_ARGS];
char fakeBuffer[8192];

extern DataSeriesOutputModule *ds_module;

static int is_tracepoint_entry(char *arr);
static void get_sys_name(char *in_buf, char *out_buf);
static void backup_entry_params();
#ifdef FSL_PRETTY_VERBOSE
static void print_keys_dbg();
#endif

__attribute__((always_inline)) inline void
get_timestamp(struct bt_clock_value *clock_value)
{
	uint64_t timestamp = 0; /* Add timestamp to the key value store */
	bt_clock_value_get_value(clock_value, &timestamp);
	strcpy(key[key_cnt++], "Timestamp");
	value[val_cnt++] = timestamp;
}

__attribute__((always_inline)) inline void
get_syscall_name(const char *syscall_name)
{
	/* Add syscall name entry/exit here */
	strcpy(key[key_cnt++], syscall_name);
	value[val_cnt++] = 0;
}

__attribute__((always_inline)) inline void print_key_value()
{
	int is_entry = is_tracepoint_entry(key[1]);
	int errnoVal = 0;

	if (*key[1] == 'c') {
		// compat syscalls
		key_cnt = 0;
		val_cnt = 0;
		return;
	}

	// Backup the key array and value array as it will be overwritten during
	// exit.
	if (is_entry == SYSCALL_ENTRY) {
		backup_entry_params();
		// print_keys_dbg();
		/* Reset counts */
		key_cnt = 0;
		val_cnt = 0;
		return;
	}
	// print_keys_dbg();

	// exit
	// create user arguents
	int itEntryArg = 0;
	for (int itBck = 4; itBck < backup_val_cnt; ++itBck, ++itEntryArg) {
		entry_args[itEntryArg] = backup_value[itBck];
	}
	for (int itVal = 5; itVal < key_cnt; ++itVal, ++itEntryArg) {
		entry_args[itEntryArg] = value[itVal];
	}

	// Get syscall name
	get_sys_name(key[1], sys_name);
	/* Then, store the common field values */
	common_fields[DS_COMMON_FIELD_TIME_CALLED] = &backup_value[0];
	common_fields[DS_COMMON_FIELD_TIME_RETURNED] = &value[0];
	common_fields[DS_COMMON_FIELD_RETURN_VALUE] = &value[4];
	common_fields[DS_COMMON_FIELD_ERRNO_NUMBER] = &errnoVal;
	common_fields[DS_COMMON_FIELD_EXECUTING_PID] = &value[3];
	common_fields[DS_COMMON_FIELD_EXECUTING_TID] = &value[3];

	////////////////////////////////////////////////////////
	if (strcmp(sys_name, "sendto") == 0 || strcmp(sys_name, "recvfrom") == 0
	    || strcmp(sys_name, "sendmsg") == 0
	    || strcmp(sys_name, "recvmsg") == 0
	    || strcmp(sys_name, "connect") == 0 || strcmp(sys_name, "bind") == 0
	    || strcmp(sys_name, "getrlimit") == 0
	    || strcmp(sys_name, "execve") == 0
	    || strcmp(sys_name, "unknown") == 0
	    || strcmp(sys_name, "getdents") == 0
	    || strcmp(sys_name, "readlink") == 0) {
		key_cnt = 0;
		val_cnt = 0;
		return;
	}
	////////////////////////////////////////////////////////

	if (strcmp(sys_name, "write") == 0) {
		v_args[0] = &fakeBuffer;
	} else if (strcmp(sys_name, "read") == 0) {
		v_args[0] = &fakeBuffer;
		uint64_t swap = entry_args[1];
		entry_args[1] = entry_args[2];
		entry_args[2] = swap;
		if (value[4] == 0)
			value[4] = swap;
	} else if (strcmp(sys_name, "clone") == 0) {
		v_args[0] = &value[3];
		v_args[1] = &value[4];
	} else if (strcmp(sys_name, "open") == 0
		   || strcmp(sys_name, "access") == 0
		   || strcmp(sys_name, "stat") == 0
		   || strcmp(sys_name, "statfs") == 0) {
		v_args[0] = &backup_value[4];
	} else {
		v_args[0] = NULL;
	}

	printf(" %s entry time %ld exit time %ld retVal %ld tid %ld\n",
	       sys_name, backup_value[0], value[0], value[4], value[3]);
	/* for (int i = 0; i < itEntryArg; ++i) { */
	/* 	printf("params[%d] = %ld\n", i, entry_args[i]); */
	/* } */
	bt_common_write_record(ds_module, sys_name, entry_args, common_fields,
			       v_args);

	/* Reset counts */
	key_cnt = 0;
	val_cnt = 0;
}

static int is_tracepoint_entry(char *arr)
{
	if (arr[TRACEPOINT_ENTRY_INDEX] == 'n')
		return 0;
	return 1;
}

static void get_sys_name(char *in_buf, char *out_buf)
{
	int offset = SYSCALL_NAME_EXIT_INDEX, i;
	for (i = 0; in_buf[i + offset] != '\0'; ++i) {
		out_buf[i] = in_buf[i + offset];
	}
	out_buf[i] = '\0';
}

static void backup_entry_params()
{
	backup_key_cnt = key_cnt;
	for (int i = 0; i < 100; ++i) {
		for (int j = 0; j < 40; ++j) {
			backup_key[i][j] = key[i][j];
		}
	}
	backup_val_cnt = val_cnt;
	for (int i = 0; i < 100; ++i) {
		backup_value[i] = value[i];
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
