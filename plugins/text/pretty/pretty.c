/*
 * pretty.c
 *
 * Babeltrace CTF Text Output Plugin
 *
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Author: Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <babeltrace/babeltrace.h>
#include <babeltrace/values.h>
#include <babeltrace/compiler-internal.h>
#include <babeltrace/common-internal.h>
#include <plugins-common.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <assert.h>
#include <strace2ds.h>

#include "pretty.h"

GQuark stream_packet_context_quarks[STREAM_PACKET_CONTEXT_QUARKS_LEN];

static
const char *plugin_options[] = {
	"color",
	"path",
	"no-delta",
	"clock-cycles",
	"clock-seconds",
	"clock-date",
	"clock-gmt",
	"verbose",
	"name-default",		/* show/hide */
	"name-payload",
	"name-context",
	"name-scope",
	"name-header",
	"field-default",	/* show/hide */
	"field-trace",
	"field-trace:hostname",
	"field-trace:domain",
	"field-trace:procname",
	"field-trace:vpid",
	"field-loglevel",
	"field-emf",
	"field-callsite",
};

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

extern DataSeriesOutputModule *ds_module;

#define TRACEPOINT_ENTRY_INDEX 9
#define SYSCALL_NAME_ENTRY_INDEX 14
#define SYSCALL_NAME_EXIT_INDEX 13
#define DS_MAX_ARGS	10

#define SYSCALL_ENTRY 0
#define SYSCALL_EXIT 1

static
void destroy_pretty_data(struct pretty_component *pretty)
{
	bt_put(pretty->input_iterator);

	if (pretty->string) {
		(void) g_string_free(pretty->string, TRUE);
	}

	if (pretty->tmp_string) {
		(void) g_string_free(pretty->tmp_string, TRUE);
	}

	if (pretty->out != stdout) {
		int ret;

		ret = fclose(pretty->out);
		if (ret) {
			perror("close output file");
		}
	}
	g_free(pretty->options.output_path);
	g_free(pretty);
}

static
struct pretty_component *create_pretty(void)
{
	struct pretty_component *pretty;

	pretty = g_new0(struct pretty_component, 1);
	if (!pretty) {
		goto end;
	}
	pretty->string = g_string_new("");
	if (!pretty->string) {
		goto error;
	}
	pretty->tmp_string = g_string_new("");
	if (!pretty->tmp_string) {
		goto error;
	}
end:
	return pretty;

error:
	g_free(pretty);
	return NULL;
}

BT_HIDDEN
void pretty_finalize(struct bt_private_component *component)
{
	void *data = bt_private_component_get_user_data(component);

	destroy_pretty_data(data);
}

static int is_tracepoint_entry(char *arr) {
	if (arr[TRACEPOINT_ENTRY_INDEX] == 'n')
		return 0;
	return 1;
}

static void get_sys_name(char *in_buf, char *out_buf) {
	int offset = SYSCALL_NAME_EXIT_INDEX, i;
	for (i = 0; in_buf[i + offset] != '\0'; ++i) {
		out_buf[i] = in_buf[i + offset];
	}
	out_buf[i] = '\0';

}

static void backup_entry_params() {
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

void *common_fields[DS_NUM_COMMON_FIELDS];
char sys_name[200];
long int entry_args[10];
void *v_args[DS_MAX_ARGS];
char fakeBuffer[8192];

__attribute__((always_inline))
static inline void print_key_value() {
	int is_entry = is_tracepoint_entry(key[1]);
	int errnoVal = 0;

        if (*key[1] == 'c') {
          // compat syscalls
          key_cnt = 0;
          val_cnt = 0;
          return;
        }
        
        // Backup the key array and value array as it will be overwritten during exit.
        if (is_entry == SYSCALL_ENTRY) {
                backup_entry_params();
		/* printf("--------------------------------------------------------\n"); */
		/* for (int i = 0; i < key_cnt; ++i) { */
		/*   printf("{ key : %s , value : %ld }\n", key[i], value[i]); */
		/* } */
		/* printf("--------------------------------------------------------\n"); */

		/* Reset counts */
		key_cnt = 0;
		val_cnt = 0;
		return;
	} 
	/* printf("--------------------------------------------------------\n"); */
	/* for (int i = 0; i < key_cnt; ++i) { */
	/* 	printf("{ key : %s , value : %ld }\n", key[i], value[i]); */
	/* } */
	/* printf("--------------------------------------------------------\n"); */

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
        if (strcmp(sys_name, "sendto") == 0 ||
	    strcmp(sys_name, "recvfrom") == 0 || 
	    strcmp(sys_name, "sendmsg") == 0 || 
	    strcmp(sys_name, "recvmsg") == 0 || 
	    strcmp(sys_name, "connect") == 0 ||
	    strcmp(sys_name, "bind") == 0 ||
	    strcmp(sys_name, "getrlimit") == 0 || 
	    strcmp(sys_name, "execve") == 0 ||
	    strcmp(sys_name, "unknown") == 0 ||
	    strcmp(sys_name, "getdents") == 0 ||
	    strcmp(sys_name, "readlink") == 0) {
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
        } else if (strcmp(sys_name, "open") == 0 ||
		   strcmp(sys_name, "access") == 0 ||
		   strcmp(sys_name, "stat") == 0 ||
		   strcmp(sys_name, "statfs") == 0) {
		v_args[0] = &backup_value[4];
	} else {
		v_args[0] = NULL;
        }

	printf(" %s entry time %ld exit time %ld retVal %ld tid %ld\n", 
	       sys_name, backup_value[0], value[0], value[4], value[3]);
	/* for (int i = 0; i < itEntryArg; ++i) { */
	/* 	printf("params[%d] = %ld\n", i, entry_args[i]); */
	/* } */
	bt_common_write_record(ds_module, sys_name, entry_args, common_fields, v_args);

	/* Reset counts */
	key_cnt = 0;
	val_cnt = 0;
}

__attribute__((always_inline))
static inline
enum bt_component_status handle_notification(struct pretty_component *pretty,
		struct bt_notification *notification)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;

	assert(pretty);

	switch (bt_notification_get_type(notification)) {
	case BT_NOTIFICATION_TYPE_EVENT:
		ret = pretty_print_event(pretty, notification);
		print_key_value();
                break;
	case BT_NOTIFICATION_TYPE_INACTIVITY:
		fprintf(stderr, "Inactivity notification\n");
		break;
	case BT_NOTIFICATION_TYPE_PACKET_BEGIN:
	case BT_NOTIFICATION_TYPE_PACKET_END:
	case BT_NOTIFICATION_TYPE_STREAM_BEGIN:
	case BT_NOTIFICATION_TYPE_STREAM_END:
		break;
	case BT_NOTIFICATION_TYPE_DISCARDED_PACKETS:
	case BT_NOTIFICATION_TYPE_DISCARDED_EVENTS:
		ret = pretty_print_discarded_elements(pretty, notification);
		break;
	default:
		fprintf(stderr, "Unhandled notification type\n");
	}

	return ret;
}

BT_HIDDEN
void pretty_port_connected(
		struct bt_private_component *component,
		struct bt_private_port *self_port,
		struct bt_port *other_port)
{
	enum bt_connection_status conn_status;
	struct bt_private_connection *connection;
	struct pretty_component *pretty;
	static const enum bt_notification_type notif_types[] = {
		BT_NOTIFICATION_TYPE_EVENT,
		BT_NOTIFICATION_TYPE_DISCARDED_PACKETS,
		BT_NOTIFICATION_TYPE_DISCARDED_EVENTS,
		BT_NOTIFICATION_TYPE_SENTINEL,
	};

	pretty = bt_private_component_get_user_data(component);
	assert(pretty);
	assert(!pretty->input_iterator);
	connection = bt_private_port_get_private_connection(self_port);
	assert(connection);
	conn_status = bt_private_connection_create_notification_iterator(
		connection, notif_types, &pretty->input_iterator);
	if (conn_status != BT_CONNECTION_STATUS_OK) {
		pretty->error = true;
	}

	bt_put(connection);
}

BT_HIDDEN
enum bt_component_status pretty_consume(struct bt_private_component *component)
{
	enum bt_component_status ret;
	struct bt_notification *notification = NULL;
	struct bt_notification_iterator *it;
	struct pretty_component *pretty =
		bt_private_component_get_user_data(component);
	enum bt_notification_iterator_status it_ret;

	if (unlikely(pretty->error)) {
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	it = pretty->input_iterator;
	it_ret = bt_notification_iterator_next(it);

	switch (it_ret) {
	case BT_NOTIFICATION_ITERATOR_STATUS_END:
		ret = BT_COMPONENT_STATUS_END;
		BT_PUT(pretty->input_iterator);
		goto end;
	case BT_NOTIFICATION_ITERATOR_STATUS_AGAIN:
		ret = BT_COMPONENT_STATUS_AGAIN;
		goto end;
	case BT_NOTIFICATION_ITERATOR_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	notification = bt_notification_iterator_get_notification(it);
	assert(notification);
	ret = handle_notification(pretty, notification);

end:
	bt_put(notification);
	return ret;
}

static
enum bt_component_status add_params_to_map(struct bt_value *plugin_opt_map)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
	unsigned int i;

	for (i = 0; i < BT_ARRAY_SIZE(plugin_options); i++) {
		const char *key = plugin_options[i];
		enum bt_value_status status;

		status = bt_value_map_insert(plugin_opt_map, key, bt_value_null);
		switch (status) {
		case BT_VALUE_STATUS_OK:
			break;
		default:
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}
	}
end:
	return ret;
}

static
bt_bool check_param_exists(const char *key, struct bt_value *object, void *data)
{
	struct pretty_component *pretty = data;
	struct bt_value *plugin_opt_map = pretty->plugin_opt_map;

	if (!bt_value_map_get(plugin_opt_map, key)) {
		fprintf(pretty->err,
			"[warning] Parameter \"%s\" unknown to \"text.pretty\" sink component\n", key);
	}
	return BT_TRUE;
}

static
enum bt_component_status apply_one_string(const char *key,
		struct bt_value *params,
		char **option)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
	struct bt_value *value = NULL;
	enum bt_value_status status;
	const char *str;

	value = bt_value_map_get(params, key);
	if (!value) {
		goto end;
	}
	if (bt_value_is_null(value)) {
		goto end;
	}
	status = bt_value_string_get(value, &str);
	switch (status) {
	case BT_VALUE_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	*option = g_strdup(str);
end:
	bt_put(value);
	return ret;
}

static
enum bt_component_status apply_one_bool(const char *key,
		struct bt_value *params,
		bool *option,
		bool *found)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
	struct bt_value *value = NULL;
	enum bt_value_status status;
	bt_bool bool_val;

	value = bt_value_map_get(params, key);
	if (!value) {
		goto end;
	}
	status = bt_value_bool_get(value, &bool_val);
	switch (status) {
	case BT_VALUE_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	*option = (bool) bool_val;
	if (found) {
		*found = true;
	}
end:
	bt_put(value);
	return ret;
}

static
void warn_wrong_color_param(struct pretty_component *pretty)
{
	fprintf(pretty->err,
		"[warning] Accepted values for the \"color\" parameter are:\n    \"always\", \"auto\", \"never\"\n");
}

static
enum bt_component_status open_output_file(struct pretty_component *pretty)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;

	if (!pretty->options.output_path) {
		goto end;
	}

	pretty->out = fopen(pretty->options.output_path, "w");
	if (!pretty->out) {
		goto error;
	}

	goto end;

error:
	ret = BT_COMPONENT_STATUS_ERROR;
end:
	return ret;
}

static
enum bt_component_status apply_params(struct pretty_component *pretty,
		struct bt_value *params)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
	enum bt_value_status status;
	bool value, found;
	char *str = NULL;

	pretty->plugin_opt_map = bt_value_map_create();
	if (!pretty->plugin_opt_map) {
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	ret = add_params_to_map(pretty->plugin_opt_map);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	/* Report unknown parameters. */
	status = bt_value_map_foreach(params, check_param_exists, pretty);
	switch (status) {
	case BT_VALUE_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	/* Known parameters. */
	pretty->options.color = PRETTY_COLOR_OPT_AUTO;
	if (bt_value_map_has_key(params, "color")) {
		struct bt_value *color_value;
		const char *color;

		color_value = bt_value_map_get(params, "color");
		if (!color_value) {
			goto end;
		}

		status = bt_value_string_get(color_value, &color);
		if (status) {
			warn_wrong_color_param(pretty);
		} else {
			if (strcmp(color, "never") == 0) {
				pretty->options.color = PRETTY_COLOR_OPT_NEVER;
			} else if (strcmp(color, "auto") == 0) {
				pretty->options.color = PRETTY_COLOR_OPT_AUTO;
			} else if (strcmp(color, "always") == 0) {
				pretty->options.color = PRETTY_COLOR_OPT_ALWAYS;
			} else {
				warn_wrong_color_param(pretty);
			}
		}

		bt_put(color_value);
	}

	ret = apply_one_string("path", params, &pretty->options.output_path);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	ret = open_output_file(pretty);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}

	value = false;		/* Default. */
	ret = apply_one_bool("no-delta", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.print_delta_field = !value;	/* Reverse logic. */

	value = false;		/* Default. */
	ret = apply_one_bool("clock-cycles", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.print_timestamp_cycles = value;

	value = false;		/* Default. */
	ret = apply_one_bool("clock-seconds", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.clock_seconds = value;

	value = false;		/* Default. */
	ret = apply_one_bool("clock-date", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.clock_date = value;

	value = false;		/* Default. */
	ret = apply_one_bool("clock-gmt", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.clock_gmt = value;

	value = false;		/* Default. */
	ret = apply_one_bool("verbose", params, &value, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	pretty->options.verbose = value;

	/* Names. */
	ret = apply_one_string("name-default", params, &str);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (!str) {
		pretty->options.name_default = PRETTY_DEFAULT_UNSET;
	} else if (!strcmp(str, "show")) {
		pretty->options.name_default = PRETTY_DEFAULT_SHOW;
	} else if (!strcmp(str, "hide")) {
		pretty->options.name_default = PRETTY_DEFAULT_HIDE;
	} else {
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	g_free(str);
	str = NULL;

	switch (pretty->options.name_default) {
	case PRETTY_DEFAULT_UNSET:
		pretty->options.print_payload_field_names = true;
		pretty->options.print_context_field_names = true;
		pretty->options.print_header_field_names = false;
		pretty->options.print_scope_field_names = false;
		break;
	case PRETTY_DEFAULT_SHOW:
		pretty->options.print_payload_field_names = true;
		pretty->options.print_context_field_names = true;
		pretty->options.print_header_field_names = true;
		pretty->options.print_scope_field_names = true;
		break;
	case PRETTY_DEFAULT_HIDE:
		pretty->options.print_payload_field_names = false;
		pretty->options.print_context_field_names = false;
		pretty->options.print_header_field_names = false;
		pretty->options.print_scope_field_names = false;
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	value = false;
	found = false;
	ret = apply_one_bool("name-payload", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_payload_field_names = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("name-context", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_context_field_names = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("name-header", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_header_field_names = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("name-scope", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_scope_field_names = value;
	}

	/* Fields. */
	ret = apply_one_string("field-default", params, &str);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (!str) {
		pretty->options.field_default = PRETTY_DEFAULT_UNSET;
	} else if (!strcmp(str, "show")) {
		pretty->options.field_default = PRETTY_DEFAULT_SHOW;
	} else if (!strcmp(str, "hide")) {
		pretty->options.field_default = PRETTY_DEFAULT_HIDE;
	} else {
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}
	g_free(str);
	str = NULL;

	switch (pretty->options.field_default) {
	case PRETTY_DEFAULT_UNSET:
		pretty->options.print_trace_field = false;
		pretty->options.print_trace_hostname_field = true;
		pretty->options.print_trace_domain_field = false;
		pretty->options.print_trace_procname_field = true;
		pretty->options.print_trace_vpid_field = true;
		pretty->options.print_loglevel_field = false;
		pretty->options.print_emf_field = false;
		pretty->options.print_callsite_field = false;
		break;
	case PRETTY_DEFAULT_SHOW:
		pretty->options.print_trace_field = true;
		pretty->options.print_trace_hostname_field = true;
		pretty->options.print_trace_domain_field = true;
		pretty->options.print_trace_procname_field = true;
		pretty->options.print_trace_vpid_field = true;
		pretty->options.print_loglevel_field = true;
		pretty->options.print_emf_field = true;
		pretty->options.print_callsite_field = true;
		break;
	case PRETTY_DEFAULT_HIDE:
		pretty->options.print_trace_field = false;
		pretty->options.print_trace_hostname_field = false;
		pretty->options.print_trace_domain_field = false;
		pretty->options.print_trace_procname_field = false;
		pretty->options.print_trace_vpid_field = false;
		pretty->options.print_loglevel_field = false;
		pretty->options.print_emf_field = false;
		pretty->options.print_callsite_field = false;
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-trace", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_trace_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-trace:hostname", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_trace_hostname_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-trace:domain", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_trace_domain_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-trace:procname", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_trace_procname_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-trace:vpid", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_trace_vpid_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-loglevel", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_loglevel_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-emf", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_emf_field = value;
	}

	value = false;
	found = false;
	ret = apply_one_bool("field-callsite", params, &value, &found);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}
	if (found) {
		pretty->options.print_callsite_field = value;
	}

end:
	bt_put(pretty->plugin_opt_map);
	pretty->plugin_opt_map = NULL;
	g_free(str);
	return ret;
}

static
void set_use_colors(struct pretty_component *pretty)
{
	switch (pretty->options.color) {
	case PRETTY_COLOR_OPT_ALWAYS:
		pretty->use_colors = true;
		break;
	case PRETTY_COLOR_OPT_AUTO:
		pretty->use_colors = pretty->out == stdout &&
			bt_common_colors_supported();
		break;
	case PRETTY_COLOR_OPT_NEVER:
		pretty->use_colors = false;
		break;
	}
}

static
void init_stream_packet_context_quarks(void)
{
	stream_packet_context_quarks[Q_TIMESTAMP_BEGIN] =
		g_quark_from_string("timestamp_begin");
	stream_packet_context_quarks[Q_TIMESTAMP_BEGIN] =
		g_quark_from_string("timestamp_begin");
	stream_packet_context_quarks[Q_TIMESTAMP_END] =
		g_quark_from_string("timestamp_end");
	stream_packet_context_quarks[Q_EVENTS_DISCARDED] =
		g_quark_from_string("events_discarded");
	stream_packet_context_quarks[Q_CONTENT_SIZE] =
		g_quark_from_string("content_size");
	stream_packet_context_quarks[Q_PACKET_SIZE] =
		g_quark_from_string("packet_size");
	stream_packet_context_quarks[Q_PACKET_SEQ_NUM] =
		g_quark_from_string("packet_seq_num");
}

BT_HIDDEN
enum bt_component_status pretty_init(
		struct bt_private_component *component,
		struct bt_value *params,
		UNUSED_VAR void *init_method_data)
{
	enum bt_component_status ret;
	struct pretty_component *pretty = create_pretty();

	if (!pretty) {
		ret = BT_COMPONENT_STATUS_NOMEM;
		goto end;
	}

	ret = bt_private_component_sink_add_input_private_port(component,
		"in", NULL, NULL);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto end;
	}

	pretty->out = stdout;
	pretty->err = stderr;

	pretty->delta_cycles = -1ULL;
	pretty->last_cycles_timestamp = -1ULL;

	pretty->delta_real_timestamp = -1ULL;
	pretty->last_real_timestamp = -1ULL;

	ret = apply_params(pretty, params);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto error;
	}

	set_use_colors(pretty);
	ret = bt_private_component_set_user_data(component, pretty);
	if (ret != BT_COMPONENT_STATUS_OK) {
		goto error;
	}

	init_stream_packet_context_quarks();

end:
	return ret;
error:
	destroy_pretty_data(pretty);
	return ret;
}
