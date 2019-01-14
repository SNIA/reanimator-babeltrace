// Copyright 2019 FSL Stony Brook University

#include <limits.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/fsl-common-internal.h>
#include <babeltrace/compat/unistd-internal.h>

DataSeriesOutputModule *ds_module;

BT_HIDDEN
void bt_common_init_dataseries(void)
{
	char *ds_fname = "/tmp/lttng.ds";
	if (ds_fname) {
		char tab_path[PATH_MAX] = {0}, xml_path[PATH_MAX] = {0};
		const char *ds_top = getenv("STRACE2DS");
		if (!ds_top)
			ds_top = "/usr/local/strace2ds";
		snprintf(tab_path, PATH_MAX, "%s/%s", ds_top,
			 "tables/snia_syscall_fields.table");
		snprintf(xml_path, PATH_MAX, "%s/%s", ds_top, "xml/");
		ds_module = ds_create_module(ds_fname, tab_path, xml_path);
		if (!ds_module)
			printf("create_ds_module failed"
			       "fname=\"%s\" table_path=\"%s\" "
			       "xml_path=\"%s\" ",
			       ds_fname, tab_path, xml_path);
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
