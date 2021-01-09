/*
 * Copyright (c) 2019 Erez Zadok
 * Copyright (c) 2019-2020 Ibrahim Umit Akgun
 * Copyright (c) 2020 Lukas Velikov */

// Copyright FSL Stony Brook University

#include "fsl-syscall-handlers.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/socket.h>

extern struct GenericSyscall persistent_syscall;
extern GHashTable *syscalls_kv_store;
extern FILE *buffer_file;
extern uint64_t event_count;

static GHashTable *lookahead_size_cache = NULL;
static GHashTable *lookahead_cache = NULL;
static void *buffer_ptr = NULL;

#define F_SET_RW_HINT 1030
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
static uint64_t set_buffer_to_vargs(long *args, void **v_args,
				    uint64_t args_idx, uint64_t v_args_idx,
				    char *arg_name);
static void set_buffer_to_vargs_from_cache(long *args, void **v_args,
					   uint64_t args_idx,
					   uint64_t v_args_idx, char *arg_name,
					   char *buffer_ptr);
static uint64_t set_buffer(uint64_t entry_event_count, long *args,
			   void **v_args, uint64_t args_idx,
			   uint64_t v_args_idx, char *arg_name);
static void *is_in_lookahead_cache(uint64_t record_id);
static void add_to_lookahead_cache(uint64_t record_id, void *buffer);
static void add_to_lookahead_size_cache(uint64_t record_id,
					uint64_t *data_size);

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
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void stat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(path, "path")
	args[0] = get_value_for_args(path);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void newstat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(filename, "filename")
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "statbuf");
}

void fstat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void newfstat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "statbuf");
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
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
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

// TODO(Umit): FIX clone system call buffer reading
int clone_parent_tid = 0, clone_child_tid = 0;
void clone_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(clone_flags, "clone_flags")
	READ_SYSCALL_ARG(newsp, "newsp")
	READ_SYSCALL_ARG(parent_tid, "parent_tid")
	READ_SYSCALL_ARG(child_tid, "child_tid")
	args[0] = get_value_for_args(clone_flags);
	args[1] = get_value_for_args(newsp);
	args[2] = get_value_for_args(parent_tid);
	args[3] = get_value_for_args(child_tid);
	args[4] = 0; // for ctid
	v_args[0] = &parent_tid;
	v_args[1] = &child_tid;
}

void truncate_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(path, "path")
	READ_SYSCALL_ARG(length, "length")
	args[0] = get_value_for_args(path);
	args[1] = get_value_for_args(length);
	v_args[0] = path->data;
}

void ftruncate_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(length, "length")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(length);
}

void link_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldname, "oldname")
	READ_SYSCALL_ARG(newname, "newname")
	args[0] = get_value_for_args(oldname);
	args[1] = get_value_for_args(newname);
	v_args[0] = oldname->data;
	v_args[1] = newname->data;
}

void linkat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(olddfd, "olddfd")
	READ_SYSCALL_ARG(oldname, "oldname")
	READ_SYSCALL_ARG(newdfd, "newdfd")
	READ_SYSCALL_ARG(newname, "newname")
	READ_SYSCALL_ARG(flags, "flags")
	args[0] = get_value_for_args(olddfd);
	args[1] = get_value_for_args(oldname);
	args[2] = get_value_for_args(newdfd);
	args[3] = get_value_for_args(newname);
	args[4] = get_value_for_args(flags);
	v_args[0] = oldname->data;
	v_args[1] = newname->data;
}

void unlink_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname")
	args[0] = get_value_for_args(pathname);
	v_args[0] = pathname->data;
}

void flock_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(cmd, "cmd");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(cmd);
}

void mkdir_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(mode);
	v_args[0] = pathname->data;
}

void openat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dfd, "dfd");
	READ_SYSCALL_ARG(filename, "filename");
	READ_SYSCALL_ARG(flags, "flags");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(dfd);
	args[1] = get_value_for_args(filename);
	args[2] = get_value_for_args(flags);
	args[3] = get_value_for_args(mode);
	v_args[0] = filename->data;
}

void rename_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldname, "oldname");
	READ_SYSCALL_ARG(newname, "newname");
	args[0] = get_value_for_args(oldname);
	args[1] = get_value_for_args(newname);
	v_args[0] = oldname->data;
	v_args[1] = newname->data;
}

void rmdir_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname");
	args[0] = get_value_for_args(pathname);
	v_args[0] = pathname->data;
}

bool exit_generated_value = true;
void exit_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(error_code, "error_code")
	args[0] = get_value_for_args(error_code);
	v_args[0] = &exit_generated_value;
}

void fchmodat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dfd, "dfd");
	READ_SYSCALL_ARG(filename, "filename");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(dfd);
	args[1] = get_value_for_args(filename);
	args[2] = get_value_for_args(mode);
	args[3] = 0;
	v_args[0] = filename->data;
}

void statfs_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname")
	args[0] = get_value_for_args(pathname);
	v_args[0] = pathname->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "buf");
}

void fstatfs_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void lstat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(filename, "filename")
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "buf");
}

void newlstat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(filename, "filename")
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "statbuf");
}

void fstatat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(dfd, "dfd")
	args[0] = get_value_for_args(dfd);

	READ_SYSCALL_ARG(filename, "filename")
	args[1] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(flag, "flag")
	args[3] = get_value_for_args(flag);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 1, "buf");
}

void newfstatat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(dfd, "dfd")
	args[0] = get_value_for_args(dfd);

	READ_SYSCALL_ARG(filename, "filename")
	args[1] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(flag, "flag")
	args[3] = get_value_for_args(flag);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 1, "statbuf");
}

void chown_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(filename, "filename");
	READ_SYSCALL_ARG(user, "user");
	READ_SYSCALL_ARG(group, "group");
	args[0] = get_value_for_args(filename);
	args[1] = get_value_for_args(user);
	args[2] = get_value_for_args(group);
	v_args[0] = filename->data;
}

void readlink_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(path, "path")
	args[0] = get_value_for_args(path);
	v_args[0] = path->data;

	READ_SYSCALL_ARG(bufsiz, "bufsiz")
	args[2] = get_value_for_args(bufsiz);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "buf");
}

void fsync_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);
}

void fdatasync_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);
}

void fallocate_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(mode, "mode")
	READ_SYSCALL_ARG(offset, "offset")
	READ_SYSCALL_ARG(len, "len")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(mode);
	args[2] = get_value_for_args(offset);
	args[3] = get_value_for_args(len);
}

void readahead_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(offset, "offset")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(offset);
	args[2] = get_value_for_args(count);
}

uint64_t mmappread_size = 0;
void mmappread_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	args[2] = 4096;

	READ_SYSCALL_ARG(pos, "index")
	args[3] = get_value_for_args(pos) * 4096;

	READ_SYSCALL_ARG(address, "addr")
	args[4] = get_value_for_args(address);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	mmappread_size =
		set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

uint64_t mmappwrite_size = 0;
void mmappwrite_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "file_desc")
	args[0] = get_value_for_args(fd);

	args[2] = 4096;

	READ_SYSCALL_ARG(pos, "index")
	args[3] = get_value_for_args(pos) * 4096;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	mmappwrite_size =
		set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void pread_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(count, "count")
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(pos, "pos")
	args[3] = get_value_for_args(pos);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void pwrite_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(count, "count")
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(pos, "pos")
	args[3] = get_value_for_args(pos);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "buf");
}

void chdir_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(filename, "filename");
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;
}

void chroot_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(filename, "filename");
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;
}

void mkdirat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dfd, "dfd");
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(dfd);
	args[1] = get_value_for_args(pathname);
	args[2] = get_value_for_args(mode);
	v_args[0] = pathname->data;
}

void symlink_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldname, "oldname");
	READ_SYSCALL_ARG(newname, "newname");
	args[0] = get_value_for_args(oldname);
	args[1] = get_value_for_args(newname);
	v_args[0] = oldname->data;
	v_args[1] = newname->data;
}

void creat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(mode);
	v_args[0] = pathname->data;
}

void faccessat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dfd, "dfd");
	READ_SYSCALL_ARG(filename, "filename");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(dfd);
	args[1] = get_value_for_args(filename);
	args[2] = get_value_for_args(mode);
	args[3] = 0;
	v_args[0] = filename->data;
}

void chmod_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(filename, "filename");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(filename);
	args[1] = get_value_for_args(mode);
	v_args[0] = filename->data;
}

void umask_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(mask, "mask");
	args[0] = get_value_for_args(mask);
}

void fchmod_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(mode, "mode");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(mode);
}

void fchdir_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	args[0] = get_value_for_args(fd);
}

void unlinkat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dfd, "dfd");
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(flag, "flag");
	args[0] = get_value_for_args(dfd);
	args[1] = get_value_for_args(pathname);
	args[2] = get_value_for_args(flag);
	v_args[0] = pathname->data;
}

void symlinkat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldname, "oldname");
	READ_SYSCALL_ARG(newdfd, "newdfd");
	READ_SYSCALL_ARG(newname, "newname");
	args[0] = get_value_for_args(oldname);
	args[1] = get_value_for_args(newdfd);
	args[2] = get_value_for_args(newname);
	v_args[0] = oldname->data;
	v_args[1] = newname->data;
}

void utime_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(filename, "filename")
	args[0] = get_value_for_args(filename);
	v_args[0] = filename->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "times");
}

void utimensat_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(dirfd, "dirfd")
	READ_SYSCALL_ARG(pathname, "pathname")
	args[0] = get_value_for_args(dirfd);
	args[1] = get_value_for_args(pathname);
	args[3] = 0; // flags

	v_args[0] = pathname->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 1, "times");
}

void mknod_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname")
	READ_SYSCALL_ARG(mode, "mode")
	READ_SYSCALL_ARG(dev, "dev")
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(mode);
	args[2] = get_value_for_args(dev);
	v_args[0] = pathname->data;
}

void mknodat_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(dirfd, "dirfd")
	READ_SYSCALL_ARG(pathname, "pathname")
	READ_SYSCALL_ARG(mode, "mode")
	READ_SYSCALL_ARG(dev, "dev")
	args[0] = get_value_for_args(dirfd);
	args[1] = get_value_for_args(pathname);
	args[2] = get_value_for_args(mode);
	args[3] = get_value_for_args(dev);
	v_args[0] = pathname->data;
}

void pipe_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 0, 0, "pipefd");
}

void dup_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldfd, "fildes")
	args[0] = get_value_for_args(oldfd);
}

void dup2_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldfd, "oldfd")
	READ_SYSCALL_ARG(newfd, "newfd")
	args[0] = get_value_for_args(oldfd);
	args[1] = get_value_for_args(newfd);
}

void dup3_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldfd, "oldfd")
	READ_SYSCALL_ARG(newfd, "newfd")
	READ_SYSCALL_ARG(flags, "flags")
	args[0] = get_value_for_args(oldfd);
	args[1] = get_value_for_args(newfd);
	args[2] = get_value_for_args(flags);
}

void fcntl_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(cmd, "cmd")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(cmd);

	READ_SYSCALL_ARG(arg, "arg")

	switch (args[1]) {
	case F_SETLK:
	case F_SETLKW:
	case F_GETLK: {
		READ_SYSCALL_ARG(record_id, "record_id")
		entry_event_count = get_value_for_args(record_id);
		set_buffer(entry_event_count, args, v_args, 2, 0, "arg");
		break;
	}
	default:
		args[2] = get_value_for_args(arg);
		break;
	}
}

void getdents_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	READ_SYSCALL_ARG(ret, "ret")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	if (get_value_for_args(ret) != 0) {
		READ_SYSCALL_ARG(record_id, "record_id")
		entry_event_count = get_value_for_args(record_id);

		set_buffer(entry_event_count, args, v_args, 1, 0, "dirp");
	} else {
		args[1] = 0;
		v_args[0] = NULL;
	}
}

void vfork_syscall_handler(long *args, void **v_args)
{
}

void set_get_rlimit_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(resource, "resource")
	args[0] = get_value_for_args(resource);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "rlim");
}

void setsid_syscall_handler(long *args, void **v_args)
{
}

void setpgid_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pid, "pid")
	READ_SYSCALL_ARG(pgid, "pgid")
	args[0] = get_value_for_args(pid);
	args[1] = get_value_for_args(pgid);
}

void getpid_syscall_handler(long *args, void **v_args)
{
}

void geteuid_syscall_handler(long *args, void **v_args)
{
}

void ioctl_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(cmd, "cmd")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(cmd);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	switch (*(unsigned int *)cmd->data) {
	case FS_IOC_GETVERSION:
	case TIOCGPGRP:
	case TIOCGWINSZ:
	case TIOCINQ:
	case TCGETS: {
		set_buffer(entry_event_count, args, v_args, 2, 0, "arg");
		break;
	}
	default:
		assert(0);
		break;
	}
}

void listxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	args[0] = get_value_for_args(pathname);
	v_args[0] = pathname->data;

	READ_SYSCALL_ARG(size, "size");
	args[2] = get_value_for_args(size);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "list");
}

void llistxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	args[0] = get_value_for_args(pathname);
	v_args[0] = pathname->data;

	READ_SYSCALL_ARG(size, "size");
	args[2] = get_value_for_args(size);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 1, "list");
}

void flistxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	args[0] = get_value_for_args(fd);

	READ_SYSCALL_ARG(size, "size");
	args[2] = get_value_for_args(size);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "list");
}

void removexattr_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	v_args[0] = pathname->data;
	v_args[1] = name->data;
}

void lremovexattr_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	v_args[0] = pathname->data;
	v_args[1] = name->data;
}

void fremovexattr_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(name, "name");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(name);
	v_args[0] = name->data;
}

void lsetxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	READ_SYSCALL_ARG(flags, "flags");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);
	args[4] = get_value_for_args(flags);
	v_args[0] = pathname->data;
	v_args[1] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 2, "value");
}

void setxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	READ_SYSCALL_ARG(flags, "flags");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);
	args[4] = get_value_for_args(flags);
	v_args[0] = pathname->data;
	v_args[1] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 2, "value");
}

void fsetxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	READ_SYSCALL_ARG(flags, "flags");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);
	args[4] = get_value_for_args(flags);
	v_args[0] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 1, "value");
}

void lgetxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);

	v_args[0] = pathname->data;
	v_args[1] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 2, "value");
}

void getxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(pathname, "pathname");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	args[0] = get_value_for_args(pathname);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);

	v_args[0] = pathname->data;
	v_args[1] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 2, "value");
}

void fgetxattr_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(name, "name");
	READ_SYSCALL_ARG(size, "size");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(name);
	args[3] = get_value_for_args(size);

	v_args[0] = name->data;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 1, "value");
}

void socket_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(domain, "family");
	READ_SYSCALL_ARG(type, "type");
	READ_SYSCALL_ARG(protocol, "protocol");
	args[0] = get_value_for_args(domain);
	args[1] = get_value_for_args(type);
	args[2] = get_value_for_args(protocol);
}

void socketpair_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(domain, "family");
	READ_SYSCALL_ARG(type, "type");
	READ_SYSCALL_ARG(protocol, "protocol");
	args[0] = get_value_for_args(domain);
	args[1] = get_value_for_args(type);
	args[2] = get_value_for_args(protocol);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 3, 0, "sv");
}

void bind_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(addrlen, "addrlen");
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(addrlen);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "umyaddr");
}

void listen_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(backlog, "backlog");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(backlog);
}

void accept_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(addrlen, "upeer_addrlen");
	args[0] = get_value_for_args(fd);
	args[1] = 0;
	args[2] = get_value_for_args(addrlen);
	v_args[0] = addrlen->data;
}

void accept4_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(addrlen, "upeer_addrlen");
	READ_SYSCALL_ARG(flags, "flags");
	args[0] = get_value_for_args(fd);
	args[1] = 0;
	args[2] = get_value_for_args(addrlen);
	args[3] = get_value_for_args(flags);
	v_args[0] = addrlen->data;
}

void getsockname_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	args[0] = get_value_for_args(fd);
	args[1] = 0;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 0, "upeer_addrlen");
}

void getpeername_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	args[0] = get_value_for_args(fd);
	args[1] = 0;
	args[2] = 0;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 2, 0, "upeer_addrlen");
}

void connect_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(addrlen, "addrlen");
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(addrlen);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "uservaddr");
}

void setsockopt_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(level, "level");
	READ_SYSCALL_ARG(optname, "optname");
	READ_SYSCALL_ARG(optlen, "optlen");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(level);
	args[2] = get_value_for_args(optname);
	args[4] = get_value_for_args(optlen);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 3, 0, "optval");
}

static long s_optlen = 0;
void getsockopt_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(level, "level");
	READ_SYSCALL_ARG(optname, "optname");
	READ_SYSCALL_ARG(optlen, "optlen");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(level);
	args[2] = get_value_for_args(optname);
	args[4] = get_value_for_args(optlen);

	s_optlen = args[4];
	v_args[0] = &s_optlen;

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 3, 1, "optval");
}

void shutdown_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd");
	READ_SYSCALL_ARG(how, "how");
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(how);
}

static int continuation_number = -1;
void execve_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(filename, "filename")
	v_args[0] = &continuation_number;
	v_args[1] = filename->data;
}

void epoll_create_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(size, "size")
	args[0] = get_value_for_args(size);
}

void epoll_create1_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(flags, "flags")
	args[0] = get_value_for_args(flags);
}

void sync_file_range_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(offset, "offset")
	READ_SYSCALL_ARG(nbytes, "nbytes")
	READ_SYSCALL_ARG(flags, "flags")
	args[0] = get_value_for_args(fd)
	args[1] = get_value_for_args(offset)
	args[2] = get_value_for_args(nbytes)
	args[3] = get_value_for_args(flags)
}

static uint64_t set_buffer(uint64_t entry_event_count, long *args,
			   void **v_args, uint64_t args_idx,
			   uint64_t v_args_idx, char *arg_name)
{
	uint64_t event_id = 0;
	uint64_t data_size = 0;
	uint64_t current_pos = 0;
	uint64_t read_size = 0;
	void *cached_buffer = NULL;
	void *buffer = NULL;
	uint64_t ret_val = 0;

	current_pos = ftell(buffer_file);
	read_size = fread(&event_id, sizeof(event_id), 1, buffer_file);

	cached_buffer = is_in_lookahead_cache(entry_event_count);
	if (cached_buffer) {
		set_buffer_to_vargs_from_cache(args, v_args, args_idx,
					       v_args_idx, arg_name,
					       cached_buffer);
		fseek(buffer_file, current_pos, SEEK_SET);
		ret_val = *(uint64_t *)g_hash_table_lookup(lookahead_size_cache,
							   &entry_event_count);
	} else {
		while (event_id != entry_event_count && read_size > 0) {
			printf("system call event ids are not matched %ld %ld\n",
			       event_id, entry_event_count);
			if (fread(&data_size, sizeof(data_size), 1, buffer_file)
			    > 0) {
				buffer = malloc(data_size);
				if (fread(buffer, sizeof(char), data_size,
					  buffer_file)
				    > 0) {
					add_to_lookahead_cache(event_id,
							       buffer);
					uint64_t *data_size_ptr =
						(uint64_t *)malloc(
							sizeof(uint64_t));
					*data_size_ptr = data_size;
					add_to_lookahead_size_cache(
						event_id, data_size_ptr);
				} else {
					assert(0);
				}
				read_size = fread(&event_id, sizeof(event_id),
						  1, buffer_file);
			} else {
				assert(0);
			}
		}
		if (event_id == entry_event_count) {
			ret_val = set_buffer_to_vargs(args, v_args, args_idx,
						      v_args_idx, arg_name);
		} else {
			v_args[v_args_idx] = NULL;
			args[args_idx] = 0;
		}
	}

	return ret_val;
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

static void add_to_lookahead_size_cache(uint64_t record_id, uint64_t *size)
{
	uint64_t *id;
	id = (uint64_t *)malloc(sizeof(uint64_t));
	*id = record_id;

	if (lookahead_size_cache == NULL) {
		lookahead_size_cache =
			g_hash_table_new(g_int64_hash, g_int64_equal);
	}
	g_hash_table_insert(lookahead_size_cache, id, size);
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

static uint64_t set_buffer_to_vargs(long *args, void **v_args,
				    uint64_t args_idx, uint64_t v_args_idx,
				    char *arg_name)
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
	return data_size;
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
