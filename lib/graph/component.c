/*
 * component.c
 *
 * Babeltrace Plugin Component
 *
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <babeltrace/graph/private-component.h>
#include <babeltrace/graph/component.h>
#include <babeltrace/graph/component-internal.h>
#include <babeltrace/graph/component-class-internal.h>
#include <babeltrace/graph/component-source-internal.h>
#include <babeltrace/graph/component-filter-internal.h>
#include <babeltrace/graph/component-sink-internal.h>
#include <babeltrace/graph/private-connection.h>
#include <babeltrace/graph/connection-internal.h>
#include <babeltrace/graph/graph-internal.h>
#include <babeltrace/graph/notification-iterator-internal.h>
#include <babeltrace/graph/private-notification-iterator.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/compiler-internal.h>
#include <babeltrace/ref.h>
#include <babeltrace/types.h>
#include <stdint.h>

static
struct bt_component * (* const component_create_funcs[])(
		struct bt_component_class *, struct bt_value *) = {
	[BT_COMPONENT_CLASS_TYPE_SOURCE] = bt_component_source_create,
	[BT_COMPONENT_CLASS_TYPE_SINK] = bt_component_sink_create,
	[BT_COMPONENT_CLASS_TYPE_FILTER] = bt_component_filter_create,
};

static
void (*component_destroy_funcs[])(struct bt_component *) = {
	[BT_COMPONENT_CLASS_TYPE_SOURCE] = bt_component_source_destroy,
	[BT_COMPONENT_CLASS_TYPE_SINK] = bt_component_sink_destroy,
	[BT_COMPONENT_CLASS_TYPE_FILTER] = bt_component_filter_destroy,
};

static
enum bt_component_status (* const component_validation_funcs[])(
		struct bt_component *) = {
	[BT_COMPONENT_CLASS_TYPE_SOURCE] = bt_component_source_validate,
	[BT_COMPONENT_CLASS_TYPE_SINK] = bt_component_sink_validate,
	[BT_COMPONENT_CLASS_TYPE_FILTER] = bt_component_filter_validate,
};

static
void bt_component_destroy(struct bt_object *obj)
{
	struct bt_component *component = NULL;
	struct bt_component_class *component_class = NULL;
	int i;

	if (!obj) {
		return;
	}

	/*
	 * The component's reference count is 0 if we're here. Increment
	 * it to avoid a double-destroy (possibly infinitely recursive).
	 * This could happen for example if the component's finalization
	 * function does bt_get() (or anything that causes bt_get() to
	 * be called) on itself (ref. count goes from 0 to 1), and then
	 * bt_put(): the reference count would go from 1 to 0 again and
	 * this function would be called again.
	 */
	obj->ref_count.count++;
	component = container_of(obj, struct bt_component, base);

	/* Call destroy listeners in reverse registration order */
	for (i = component->destroy_listeners->len - 1; i >= 0; i--) {
		struct bt_component_destroy_listener *listener =
			&g_array_index(component->destroy_listeners,
				struct bt_component_destroy_listener, i);

		listener->func(component, listener->data);
	}

	component_class = component->class;

	/*
	 * User data is destroyed first, followed by the concrete component
	 * instance.
	 */
	if (component->class->methods.finalize) {
		component->class->methods.finalize(
			bt_private_component_from_component(component));
	}

	if (component->destroy) {
		component->destroy(component);
	}

	if (component->input_ports) {
		g_ptr_array_free(component->input_ports, TRUE);
	}

	if (component->output_ports) {
		g_ptr_array_free(component->output_ports, TRUE);
	}

	if (component->destroy_listeners) {
		g_array_free(component->destroy_listeners, TRUE);
	}

	g_string_free(component->name, TRUE);
	bt_put(component_class);
	g_free(component);
}

struct bt_component *bt_component_from_private_component(
		struct bt_private_component *private_component)
{
	return bt_get(bt_component_from_private(private_component));
}

enum bt_component_class_type bt_component_get_class_type(
		struct bt_component *component)
{
	return component ? component->class->type : BT_COMPONENT_CLASS_TYPE_UNKNOWN;
}

static
struct bt_port *bt_component_add_port(
		struct bt_component *component, GPtrArray *ports,
		enum bt_port_type port_type, const char *name, void *user_data)
{
	size_t i;
	struct bt_port *new_port = NULL;
	struct bt_graph *graph = NULL;

	if (!name || strlen(name) == 0) {
		goto end;
	}

	/* Look for a port having the same name. */
	for (i = 0; i < ports->len; i++) {
		const char *port_name;
		struct bt_port *port = g_ptr_array_index(
				ports, i);

		port_name = bt_port_get_name(port);
		if (!port_name) {
			continue;
		}

		if (!strcmp(name, port_name)) {
			/* Port name clash, abort. */
			goto end;
		}
	}

	new_port = bt_port_create(component, port_type, name, user_data);
	if (!new_port) {
		goto end;
	}

	/*
	 * No name clash, add the port.
	 * The component is now the port's parent; it should _not_
	 * hold a reference to the port since the port's lifetime
	 * is now protected by the component's own lifetime.
	 */
	g_ptr_array_add(ports, new_port);

	/*
	 * Notify the graph's creator that a new port was added.
	 */
	graph = bt_component_get_graph(component);
	if (graph) {
		bt_graph_notify_port_added(graph, new_port);
		BT_PUT(graph);
	}

end:
	return new_port;
}

BT_HIDDEN
int64_t bt_component_get_input_port_count(struct bt_component *comp)
{
	assert(comp);
	return (int64_t) comp->input_ports->len;
}

BT_HIDDEN
int64_t bt_component_get_output_port_count(struct bt_component *comp)
{
	assert(comp);
	return (int64_t) comp->output_ports->len;
}

struct bt_component *bt_component_create_with_init_method_data(
		struct bt_component_class *component_class, const char *name,
		struct bt_value *params, void *init_method_data)
{
	int ret;
	struct bt_component *component = NULL;
	enum bt_component_class_type type;

	bt_get(params);

	if (!component_class) {
		goto end;
	}

	type = bt_component_class_get_type(component_class);
	if (type <= BT_COMPONENT_CLASS_TYPE_UNKNOWN ||
			type > BT_COMPONENT_CLASS_TYPE_FILTER) {
		goto end;
	}

	/*
	 * Parameters must be a map value, but we create a convenient
	 * empty one if it's NULL.
	 */
	if (params) {
		if (!bt_value_is_map(params)) {
			goto end;
		}
	} else {
		params = bt_value_map_create();
		if (!params) {
			goto end;
		}
	}

	component = component_create_funcs[type](component_class, params);
	if (!component) {
		goto end;
	}

	bt_object_init(component, bt_component_destroy);
	component->class = bt_get(component_class);
	component->destroy = component_destroy_funcs[type];
	component->name = g_string_new(name);
	if (!component->name) {
		BT_PUT(component);
		goto end;
	}

	component->input_ports = g_ptr_array_new_with_free_func(
		bt_object_release);
	if (!component->input_ports) {
		BT_PUT(component);
		goto end;
	}

	component->output_ports = g_ptr_array_new_with_free_func(
		bt_object_release);
	if (!component->output_ports) {
		BT_PUT(component);
		goto end;
	}

	component->destroy_listeners = g_array_new(FALSE, TRUE,
		sizeof(struct bt_component_destroy_listener));
	if (!component->destroy_listeners) {
		BT_PUT(component);
		goto end;
	}

	component->initializing = BT_TRUE;

	if (component_class->methods.init) {
		ret = component_class->methods.init(
			bt_private_component_from_component(component), params,
			init_method_data);
		component->initializing = BT_FALSE;
		if (ret != BT_COMPONENT_STATUS_OK) {
			BT_PUT(component);
			goto end;
		}
	}

	component->initializing = BT_FALSE;
	ret = component_validation_funcs[type](component);
	if (ret != BT_COMPONENT_STATUS_OK) {
		BT_PUT(component);
		goto end;
	}

	bt_component_class_freeze(component->class);
end:
	bt_put(params);
	return component;
}

struct bt_component *bt_component_create(
		struct bt_component_class *component_class, const char *name,
		struct bt_value *params)
{
	return bt_component_create_with_init_method_data(component_class, name,
		params, NULL);
}

const char *bt_component_get_name(struct bt_component *component)
{
	const char *ret = NULL;

	if (!component) {
		goto end;
	}

	ret = component->name->len == 0 ? NULL : component->name->str;
end:
	return ret;
}

struct bt_component_class *bt_component_get_class(
		struct bt_component *component)
{
	return component ? bt_get(component->class) : NULL;
}

void *bt_private_component_get_user_data(
		struct bt_private_component *private_component)
{
	struct bt_component *component =
		bt_component_from_private(private_component);

	return component ? component->user_data : NULL;
}

enum bt_component_status bt_private_component_set_user_data(
		struct bt_private_component *private_component,
		void *data)
{
	struct bt_component *component =
		bt_component_from_private(private_component);
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;

	if (!component || !component->initializing) {
		ret = BT_COMPONENT_STATUS_INVALID;
		goto end;
	}

	component->user_data = data;
end:
	return ret;
}

BT_HIDDEN
void bt_component_set_graph(struct bt_component *component,
		struct bt_graph *graph)
{
	struct bt_object *parent = bt_object_get_parent(&component->base);

	assert(!parent || parent == &graph->base);
	if (!parent) {
		bt_object_set_parent(component, &graph->base);
	}
	bt_put(parent);
}

struct bt_graph *bt_component_get_graph(
		struct bt_component *component)
{
	return (struct bt_graph *) bt_object_get_parent(&component->base);
}

static
struct bt_port *bt_component_get_port_by_name(GPtrArray *ports,
		const char *name)
{
	size_t i;
	struct bt_port *ret_port = NULL;

	assert(name);

	for (i = 0; i < ports->len; i++) {
		struct bt_port *port = g_ptr_array_index(ports, i);
		const char *port_name = bt_port_get_name(port);

		if (!port_name) {
			continue;
		}

		if (!strcmp(name, port_name)) {
			ret_port = bt_get(port);
			break;
		}
	}

	return ret_port;
}

BT_HIDDEN
struct bt_port *bt_component_get_input_port_by_name(struct bt_component *comp,
		const char *name)
{
	assert(comp);

	return bt_component_get_port_by_name(comp->input_ports, name);
}

BT_HIDDEN
struct bt_port *bt_component_get_output_port_by_name(struct bt_component *comp,
		const char *name)
{
	assert(comp);

	return bt_component_get_port_by_name(comp->output_ports, name);
}

static
struct bt_port *bt_component_get_port_by_index(GPtrArray *ports, uint64_t index)
{
	struct bt_port *port = NULL;

	if (index >= ports->len) {
		goto end;
	}

	port = bt_get(g_ptr_array_index(ports, index));
end:
	return port;
}

BT_HIDDEN
struct bt_port *bt_component_get_input_port_by_index(struct bt_component *comp,
		uint64_t index)
{
	assert(comp);

	return bt_component_get_port_by_index(comp->input_ports, index);
}

BT_HIDDEN
struct bt_port *bt_component_get_output_port_by_index(struct bt_component *comp,
		uint64_t index)
{
	assert(comp);

	return bt_component_get_port_by_index(comp->output_ports, index);
}

BT_HIDDEN
struct bt_port *bt_component_add_input_port(
		struct bt_component *component, const char *name,
		void *user_data)
{
	return bt_component_add_port(component, component->input_ports,
		BT_PORT_TYPE_INPUT, name, user_data);
}

BT_HIDDEN
struct bt_port *bt_component_add_output_port(
		struct bt_component *component, const char *name,
		void *user_data)
{
	return bt_component_add_port(component, component->output_ports,
		BT_PORT_TYPE_OUTPUT, name, user_data);
}

static
void bt_component_remove_port_by_index(struct bt_component *component,
		GPtrArray *ports, size_t index)
{
	struct bt_port *port;
	struct bt_graph *graph;

	assert(ports);
	assert(index < ports->len);
	port = g_ptr_array_index(ports, index);

	/* Disconnect both ports of this port's connection, if any */
	if (port->connection) {
		bt_connection_disconnect_ports(port->connection);
	}

	/* Remove from parent's array of ports (weak refs) */
	g_ptr_array_remove_index(ports, index);

	/* Detach port from its component parent */
	BT_PUT(port->base.parent);

	/*
	 * Notify the graph's creator that a port is removed.
	 */
	graph = bt_component_get_graph(component);
	if (graph) {
		bt_graph_notify_port_removed(graph, component, port);
		BT_PUT(graph);
	}
}

BT_HIDDEN
enum bt_component_status bt_component_remove_port(
		struct bt_component *component, struct bt_port *port)
{
	size_t i;
	enum bt_component_status status = BT_COMPONENT_STATUS_OK;
	GPtrArray *ports = NULL;

	if (!component || !port) {
		status = BT_COMPONENT_STATUS_INVALID;
		goto end;
	}

	if (bt_port_get_type(port) == BT_PORT_TYPE_INPUT) {
		ports = component->input_ports;
	} else if (bt_port_get_type(port) == BT_PORT_TYPE_OUTPUT) {
		ports = component->output_ports;
	}

	assert(ports);

	for (i = 0; i < ports->len; i++) {
		struct bt_port *cur_port = g_ptr_array_index(ports, i);

		if (cur_port == port) {
			bt_component_remove_port_by_index(component,
				ports, i);
			goto end;
		}
	}

	status = BT_COMPONENT_STATUS_NOT_FOUND;
end:
	return status;
}

BT_HIDDEN
enum bt_component_status bt_component_accept_port_connection(
		struct bt_component *comp, struct bt_port *self_port,
		struct bt_port *other_port)
{
	enum bt_component_status status = BT_COMPONENT_STATUS_OK;

	assert(comp);
	assert(self_port);
	assert(other_port);

	if (comp->class->methods.accept_port_connection) {
		status = comp->class->methods.accept_port_connection(
			bt_private_component_from_component(comp),
			bt_private_port_from_port(self_port),
			other_port);
	}

	return status;
}

BT_HIDDEN
void bt_component_port_connected(struct bt_component *comp,
		struct bt_port *self_port, struct bt_port *other_port)
{
	assert(comp);
	assert(self_port);
	assert(other_port);

	if (comp->class->methods.port_connected) {
		comp->class->methods.port_connected(
			bt_private_component_from_component(comp),
			bt_private_port_from_port(self_port), other_port);
	}
}

BT_HIDDEN
void bt_component_port_disconnected(struct bt_component *comp,
		struct bt_port *port)
{
	assert(comp);
	assert(port);

	if (comp->class->methods.port_disconnected) {
		comp->class->methods.port_disconnected(
			bt_private_component_from_component(comp),
			bt_private_port_from_port(port));
	}
}

BT_HIDDEN
void bt_component_add_destroy_listener(struct bt_component *component,
		bt_component_destroy_listener_func func, void *data)
{
	struct bt_component_destroy_listener listener;

	assert(component);
	assert(func);
	listener.func = func;
	listener.data = data;
	g_array_append_val(component->destroy_listeners, listener);
}

BT_HIDDEN
void bt_component_remove_destroy_listener(struct bt_component *component,
		bt_component_destroy_listener_func func, void *data)
{
	size_t i;

	assert(component);
	assert(func);

	for (i = 0; i < component->destroy_listeners->len; i++) {
		struct bt_component_destroy_listener *listener =
			&g_array_index(component->destroy_listeners,
				struct bt_component_destroy_listener, i);

		if (listener->func == func && listener->data == data) {
			g_array_remove_index(component->destroy_listeners, i);
			i--;
		}
	}
}
