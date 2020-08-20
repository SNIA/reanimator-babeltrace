// Copyright 2019 FSL Stony Brook University

#ifndef FSL_COMMON_INTERNAL
#define FSL_COMMON_INTERNAL

#include <babeltrace/babeltrace-internal.h>
#include <stdbool.h>
#include <strace2ds.h>

extern char *program_invocation_name;

BT_HIDDEN
void bt_common_init_dataseries(char *ds_fname);

BT_HIDDEN
void bt_common_write_record(DataSeriesOutputModule *ds_module,
                            const char *extent_name, long *args,
                            void *common_fields[DS_NUM_COMMON_FIELDS],
                            void **v_args);
BT_HIDDEN
void bt_common_destroy_module();

BT_HIDDEN
char *bt_common_get_buffer_file_path(void);

BT_HIDDEN
void bt_common_set_buffer_file_path(char *file_path);

BT_HIDDEN
bool bt_common_is_fsl_ds_enabled(void);

#endif
