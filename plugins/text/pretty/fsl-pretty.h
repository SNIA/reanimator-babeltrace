/*
 * Copyright (c) 2019 Erez Zadok
 * Copyright (c) 2019-2020 Ibrahim Umit Akgun
 * Copyright (c) 2020 Lukas Velikov */

// Copyright 2019 FSL Stony Brook University

#ifndef FSL_PRETTY
#define FSL_PRETTY

#include <glib.h>
#include <babeltrace/ctf-ir/clock-value-internal.h>

#define SYSCALL_NAME_ENTRY_INDEX 14
#define SYSCALL_NAME_EXIT_INDEX 13
#define DS_MAX_ARGS 10

#define PARAMETER_COUNT 100
#define KEY_LENGTH 256

#define SYSCALL_COMPAT -1
#define SYSCALL_ENTRY 0
#define SYSCALL_EXIT 1

enum syscall_event_type {
	compat_event,
	entry_event,
	exit_event,
        mm_filemap_event,
        writeback_event,
	unknown_event
} events;
typedef enum syscall_event_type SyscallEvent;

enum syscall_data_type { Integer, String, Double } data_type;
typedef enum syscall_data_type ValueType;

struct GenericSyscall {
	GHashTable *key_value;
};

struct SyscallArgType {
	void *data;
	ValueType type;
};
typedef struct SyscallArgType SyscallArgument;

typedef void (*syscall_handler)(long *, void **);

// #define FSL_PRETTY_VERBOSE

#define GET_THREAD_ID()                                                        \
	*(uint64_t *)((SyscallArgument *)g_hash_table_lookup(                  \
			      persistent_syscall.key_value, "tid"))            \
		 ->data

#define GET_PROCESS_ID()                                                       \
	*(uint64_t *)((SyscallArgument *)g_hash_table_lookup(                  \
			      persistent_syscall.key_value, "pid"))            \
		 ->data

#define GET_SYSCALL_NAME()                                                     \
	(char *)((SyscallArgument *)g_hash_table_lookup(                       \
			 persistent_syscall.key_value, "syscall_name"))        \
		->data

void fsl_dump_values();
void get_timestamp(struct bt_clock_value *clock_value);
void get_syscall_name(const char *syscall_name);
void get_integer_field(char *key_, uint64_t value_);
void get_double_field(char *key_, double value_);
void get_string_field(char *key_, const char *value_);

#endif
