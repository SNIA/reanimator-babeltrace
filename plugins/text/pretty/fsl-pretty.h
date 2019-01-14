// Copyright 2019 FSL Stony Brook University

#ifndef FSL_PRETTY
#define FSL_PRETTY

#include <babeltrace/ctf-ir/clock-value-internal.h>

#define TRACEPOINT_ENTRY_INDEX 9
#define SYSCALL_NAME_ENTRY_INDEX 14
#define SYSCALL_NAME_EXIT_INDEX 13
#define DS_MAX_ARGS	10

#define SYSCALL_ENTRY 0
#define SYSCALL_EXIT 1

// #define FSL_PRETTY_VERBOSE

void print_key_value();
void get_timestamp(struct bt_clock_value *clock_value);
void get_syscall_name(const char *syscall_name);

#endif
