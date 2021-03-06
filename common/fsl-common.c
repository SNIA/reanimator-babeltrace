/*
 * Copyright (c) 2019 Erez Zadok
 * Copyright (c) 2019-2020 Ibrahim Umit Akgun
 * Copyright (c) 2020 Lukas Velikov */

// Copyright 2019 FSL Stony Brook University

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/fsl-common-internal.h>
#include <babeltrace/compat/unistd-internal.h>

DataSeriesOutputModule *ds_module;
char ds_buffer_file_path[PATH_MAX];
bool isDSEnabled = false;

BT_HIDDEN
void bt_common_init_dataseries(char *ds_fname)
{
	if (ds_fname) {
		char ds_top[PATH_MAX] = {0};
		char tab_path[PATH_MAX] = {0};
		char xml_path[PATH_MAX] = {0};
		struct stat lib_info;

		int lib_search_return = stat(STRACE2DSDIR, &lib_info);
		if (lib_search_return == 0 && S_ISDIR(lib_info.st_mode)) {
			strncpy(ds_top, STRACE2DSDIR, PATH_MAX);
		} else {
			strncpy(ds_top, "/usr/local/strace2ds", PATH_MAX);
		}
		snprintf(tab_path, PATH_MAX, "%s/%s", ds_top,
			 "tables/snia_syscall_fields.table");
		snprintf(xml_path, PATH_MAX, "%s/%s", ds_top, "xml/");
		ds_module = ds_create_module(ds_fname, tab_path, xml_path);
		if (!ds_module) {
			printf("create_ds_module failed"
				"fname=\"%s\" table_path=\"%s\" "
				"xml_path=\"%s\" ",
				ds_fname, tab_path, xml_path);
		}
	}
}

BT_HIDDEN
void bt_common_write_record(DataSeriesOutputModule *ds_module,
			    const char *extent_name, long *args,
			    void *common_fields[DS_NUM_COMMON_FIELDS],
			    void **v_args)
{
	int syscallNum = BT_FSL_SYSCALL_NUM;
	common_fields[DS_COMMON_FIELD_SYSCALL_NUM] = &syscallNum;
	ds_write_record(ds_module, extent_name, args, common_fields, v_args);
}

BT_HIDDEN
void bt_common_destroy_module()
{
	ds_destroy_module(ds_module);
}

BT_HIDDEN
char *bt_common_get_buffer_file_path(void)
{
	return ds_buffer_file_path;
}

BT_HIDDEN
void bt_common_set_buffer_file_path(char *file_path)
{
	strcpy(ds_buffer_file_path, file_path);
	isDSEnabled = true;
}

BT_HIDDEN
bool bt_common_is_fsl_ds_enabled(void)
{
	return isDSEnabled;
}
