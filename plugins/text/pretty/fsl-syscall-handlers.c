// Copyright FSL Stony Brook University

#include "fsl-syscall-handlers.h"
#include <fcntl.h>

extern struct GenericSyscall persistent_syscall;
extern GHashTable *syscalls_kv_store;
extern FILE *buffer_file;
extern uint64_t event_count;

static GHashTable *lookahead_cache = NULL;
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
static void set_buffer(uint64_t entry_event_count, long *args, void **v_args,
		       uint64_t args_idx, uint64_t v_args_idx, char *arg_name);
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
	READ_SYSCALL_ARG(oldfd, "oldfd")
	args[0] = get_value_for_args(oldfd);
}

void dup2_syscall_handler(long *args, void **v_args)
{
	READ_SYSCALL_ARG(oldfd, "oldfd")
	READ_SYSCALL_ARG(newfd, "newfd")
	args[0] = get_value_for_args(oldfd);
	args[1] = get_value_for_args(newfd);
}

void fcntl_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(cmd, "cmd")
	args[0] = get_value_for_args(fd);
	args[1] = get_value_for_args(cmd);

	if (args[1] == F_SETLK || args[1] == F_SETLKW || args[1] == F_GETLK) {
		READ_SYSCALL_ARG(record_id, "record_id")
		entry_event_count = get_value_for_args(record_id);

		set_buffer(entry_event_count, args, v_args, 2, 0, "arg");
	} else {
		READ_SYSCALL_ARG(arg, "arg")
		args[2] = get_value_for_args(arg);
	}
}

void getdents_syscall_handler(long *args, void **v_args)
{
	uint64_t entry_event_count = 0;

	READ_SYSCALL_ARG(fd, "fd")
	READ_SYSCALL_ARG(count, "count")
	args[0] = get_value_for_args(fd);
	args[2] = get_value_for_args(count);

	READ_SYSCALL_ARG(record_id, "record_id")
	entry_event_count = get_value_for_args(record_id);

	set_buffer(entry_event_count, args, v_args, 1, 0, "dirp");
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

static void set_buffer(uint64_t entry_event_count, long *args, void **v_args,
		       uint64_t args_idx, uint64_t v_args_idx, char *arg_name)
{
	uint64_t event_id = 0;
	uint64_t data_size = 0;
	uint64_t current_pos = 0;
	void *cached_buffer = NULL;
	void *buffer = NULL;

	current_pos = ftell(buffer_file);
	fread(&event_id, sizeof(event_id), 1, buffer_file);

	cached_buffer = is_in_lookahead_cache(entry_event_count);
	if (cached_buffer) {
		set_buffer_to_vargs_from_cache(args, v_args, args_idx,
					       v_args_idx, arg_name,
					       cached_buffer);
		fseek(buffer_file, current_pos, SEEK_SET);
	} else {
		while (event_id != entry_event_count) {
			printf("system call event ids are not matched %ld %ld\n",
			       event_id, entry_event_count);
			fread(&data_size, sizeof(data_size), 1, buffer_file);
			buffer = malloc(data_size);
			fread(buffer, sizeof(char), data_size, buffer_file);
			add_to_lookahead_cache(event_id, buffer);
			fread(&event_id, sizeof(event_id), 1, buffer_file);
		}
		if (event_id == entry_event_count) {
			set_buffer_to_vargs(args, v_args, args_idx, v_args_idx,
					    arg_name);
		} else {
			assert(0);
		}
	}
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
