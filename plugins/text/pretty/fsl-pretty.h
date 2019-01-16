// Copyright 2019 FSL Stony Brook University

#ifndef FSL_PRETTY
#define FSL_PRETTY

#include <glib-2.0/glib/ghash.h>
#include <babeltrace/ctf-ir/clock-value-internal.h>

#define SYSCALL_NAME_ENTRY_INDEX 14
#define SYSCALL_NAME_EXIT_INDEX 13
#define DS_MAX_ARGS 10

#define PARAMETER_COUNT 100
#define KEY_LENGTH 256

#define SYSCALL_COMPAT -1
#define SYSCALL_ENTRY 0
#define SYSCALL_EXIT 1

struct GenericSyscall {
	GHashTable *key_value;
};

enum syscall_event_type {
	compat_event,
	entry_event,
	exit_event,
	unknown_event
} events;
typedef enum syscall_event_type SyscallEvent;

// #define FSL_PRETTY_VERBOSE

void print_key_value();
void get_timestamp(struct bt_clock_value *clock_value);
void get_syscall_name(const char *syscall_name);
void get_integer_field(char *key_, uint64_t value_);
void get_double_field(char *key_, double value_);
void get_string_field(char *key_, const char *value_);

#endif
