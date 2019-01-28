// Copyright 2019 FSL Stony Brook University

#ifndef FSL_COMMON_INTERNAL
#define FSL_COMMON_INTERNAL

#include <babeltrace/babeltrace-internal.h>
#include <stdbool.h>
#include <strace2ds.h>

BT_HIDDEN
void bt_common_init_dataseries(char *ds_fname);

BT_HIDDEN
void bt_common_write_record(DataSeriesOutputModule *ds_module,
                            const char *extent_name, long *args,
                            void *common_fields[DS_NUM_COMMON_FIELDS],
                            void **v_args);
BT_HIDDEN
void bt_common_destroy_module();

#endif
