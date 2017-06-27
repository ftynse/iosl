#include "iosl.h"

#include <isl/map.h>
#include <isl/set.h>
#include <isl/union_map.h>
#include <isl/union_set.h>
#include <isl/schedule.h>
#include <isl/printer.h>
#include <isl/id.h>

#include <osl/osl.h>

#define WARNINGS

#ifdef WARNINGS
#define WARN(text) \
	do { \
		fprintf(stderr, "[iosl] Warning: %s\n", text); \
	} while (0)
#endif

osl_relation_p osl_relation_from_isl_basic_set(__isl_take isl_basic_set *bset)
{
	int n_out, n_param, n_local;
	osl_relation_p relation;
	isl_ctx *ctx;
	isl_printer *p;
	char *string;

	if (!bset) {
		WARN("converting NULL basic set");
		return NULL;
	}

	ctx = isl_basic_set_get_ctx(bset);

	n_out = isl_basic_set_dim(bset, isl_dim_set);
	n_param = isl_basic_set_dim(bset, isl_dim_param);
	n_local = isl_basic_set_dim(bset, isl_dim_div);

	p = isl_printer_to_str(ctx);
	p = isl_printer_set_output_format(p, ISL_FORMAT_EXT_POLYLIB);
	p = isl_printer_print_basic_set(p, bset);
	string = isl_printer_get_str(p);
	isl_printer_free(p);
	isl_basic_set_free(bset);

	relation = osl_relation_sread_polylib(&string);
	osl_relation_set_attributes(relation, n_out, 0, n_local, n_param);
	return relation;
}

osl_relation_p osl_relation_from_isl_basic_map(__isl_take isl_basic_map *bmap)
{
	int n_in, n_out, n_param, n_local;
	osl_relation_p relation;
	isl_ctx *ctx;
	isl_printer *p;
	char *string;
	isl_map *map;

	if (!bmap) {
		WARN("converting NULL basic map");
		return NULL;
	}

	ctx = isl_basic_map_get_ctx(bmap);

	n_in = isl_basic_map_dim(bmap, isl_dim_in);
	n_out = isl_basic_map_dim(bmap, isl_dim_out);
	n_param = isl_basic_map_dim(bmap, isl_dim_param);
	n_local = isl_basic_map_dim(bmap, isl_dim_div);

	p = isl_printer_to_str(ctx);
	p = isl_printer_set_output_format(p, ISL_FORMAT_EXT_POLYLIB);
	map = isl_map_from_basic_map(bmap);
	p = isl_printer_print_map(p, map);
	isl_map_free(map);
	string = isl_printer_get_str(p);
	isl_printer_free(p);
	isl_basic_map_free(bmap);

	relation = osl_relation_sread_polylib(&string);
	osl_relation_set_attributes(relation, n_out, n_in, n_local, n_param);
	return relation;
}

static isl_stat convert_basic_set_to_osl_relation(
		__isl_take isl_basic_set *bset, void *user)
{
	osl_relation_p *result = (osl_relation_p *) user;
	osl_relation_p current = osl_relation_from_isl_basic_set(bset);
	if (!current)
		return isl_stat_error;
	osl_relation_add(result, current);
	user = (void *) result;
	return isl_stat_ok;
}


osl_relation_p osl_relation_from_isl_set(__isl_take isl_set *set)
{
	osl_relation_p result = NULL;
	if (isl_set_foreach_basic_set(set, &convert_basic_set_to_osl_relation,
				      &result) != isl_stat_ok) {
		if (result)
			osl_relation_free(result);
		isl_set_free(set);
		return NULL;
	}
	isl_set_free(set);
	return result;
}

static isl_stat convert_basic_map_to_osl_relation(
		__isl_take isl_basic_map *bmap, void *user)
{
	osl_relation_p *result = (osl_relation_p *) user;
	osl_relation_p current = osl_relation_from_isl_basic_map(bmap);
	if (!current)
		return isl_stat_error;
	osl_relation_add(result, current);
	user = (void *) result;
	return isl_stat_ok;
}

osl_relation_p osl_relation_from_isl_map(__isl_take isl_map *map)
{
	osl_relation_p result = NULL;
	if (isl_map_foreach_basic_map(map, &convert_basic_map_to_osl_relation,
				      &result) != isl_stat_ok) {
		if (result)
			osl_relation_free(result);
		isl_map_free(map);
		return NULL;
	}
	isl_map_free(map);
	return result;
}

struct osl_stmt_builder {
	osl_statement_p stmt;
	isl_id *id;
	struct osl_stmt_builder *next;
};

static void free_stmt_builder(struct osl_stmt_builder *builder) {
	while (builder) {
		struct osl_stmt_builder *next = builder->next;
		if (builder->id)
			isl_id_free(builder->id);
		if (builder->stmt)
			osl_statement_free(builder->stmt);
		free(builder);
		builder = next;
	}
}

static struct osl_stmt_builder *wrap_domain_set(__isl_take isl_set *domain_set)
{
	struct osl_stmt_builder *builder = (struct osl_stmt_builder *)
			malloc(sizeof(struct osl_stmt_builder));
	builder->id = isl_set_get_tuple_id(domain_set);
	builder->stmt = osl_statement_malloc();
	builder->stmt->domain = osl_relation_from_isl_set(domain_set);
	osl_relation_set_type(builder->stmt->domain, OSL_TYPE_DOMAIN);
	builder->next = NULL;

	return builder;
}

static isl_stat add_osl_stmt_builder_to_list(__isl_take isl_set *domain_set,
					     void *user)
{
	struct osl_stmt_builder *current = wrap_domain_set(domain_set);
	struct osl_stmt_builder *builder_list =
				*(struct osl_stmt_builder **) user;
	if (!builder_list) {
		*(struct osl_stmt_builder **) user = current;
	} else {
		while (builder_list->next) {
			builder_list = builder_list->next;
		}
		builder_list->next = current;
	}
	return isl_stat_ok;
}

static osl_statement_p find_statement_by_tuple_id(
		struct osl_stmt_builder *builders, __isl_keep isl_id *id)
{
	for ( ; builders != NULL; builders = builders->next) {
		if (builders->id == id)
			return builders->stmt;
	}
	return NULL;
}

static void relation_add_array_id(osl_relation_p relation, int idx) {
	while (relation) {
		osl_relation_insert_blank_row(relation, 0);
		osl_relation_insert_blank_column(relation, 1);
		osl_int_set_si(osl_util_get_precision(),
			       &relation->m[0][1], -1);
		osl_int_set_si(osl_util_get_precision(),
			       &relation->m[0][relation->nb_columns - 1], idx);
		relation->nb_output_dims += 1;
		relation = relation->next;
	}
}

static void attach_access(__isl_take isl_map *map,
			  struct osl_stmt_builder *builders,
			  osl_arrays_p arrays, int type) {
	isl_id *stmt_id;
	const char *array_name;
	osl_relation_p relation;
	int idx;
	osl_statement_p stmt;

	stmt_id = isl_map_get_tuple_id(map, isl_dim_in);
	stmt = find_statement_by_tuple_id(builders, stmt_id);
	isl_id_free(stmt_id);

	if (!stmt) {
		WARN("access map for a statement not present in the domain");
		return;
	}

	array_name = isl_map_get_tuple_name(map, isl_dim_out);

	idx = osl_arrays_get_index_from_name(arrays, (char *) array_name);
	if (idx == arrays->nb_names) {
		osl_arrays_add(arrays, idx + 1, (char *) array_name);
	}
	idx += 1;

	relation = osl_relation_from_isl_map(map);
	relation_add_array_id(relation, idx);
	osl_relation_set_type(relation, type);

	osl_relation_list_add(&stmt->access, osl_relation_list_node(relation));
}

struct add_access_relation_data {
	osl_arrays_p arrays;
	int type;
	struct osl_stmt_builder *builders;
};

static isl_stat add_access_relation_to_list(__isl_take isl_map *map, void *user)
{
	struct add_access_relation_data *data =
			(struct add_access_relation_data *) user;
	attach_access(map, data->builders, data->arrays, data->type);
	return isl_stat_ok;
}

static void set_schedule(__isl_take isl_map *schedule_map,
			 struct osl_stmt_builder *builders)
{
	osl_statement_p stmt;
	isl_id *stmt_id;

	stmt_id = isl_map_get_tuple_id(schedule_map, isl_dim_in);
	stmt = find_statement_by_tuple_id(builders, stmt_id);
	isl_id_free(stmt_id);

	if (!stmt) {
		WARN("schedule for a statement not present in the domain");
		return;
	}

	stmt->scattering = osl_relation_from_isl_map(schedule_map);
	osl_relation_set_type(stmt->scattering, OSL_TYPE_SCATTERING);
}

static isl_stat add_schedule(__isl_take isl_map *schedule_map, void *user)
{
	struct osl_stmt_builder *builders =
			(struct osl_stmt_builder *) user;
	set_schedule(schedule_map, builders);
	return isl_stat_ok;
}

osl_scop_p osl_scop_from_isl(__isl_keep isl_set *context,
			     __isl_keep isl_union_set *domain,
			     __isl_keep isl_union_map *reads,
			     __isl_keep isl_union_map *writes,
			     __isl_keep isl_schedule *schedule)
{
	osl_scop_p scop = osl_scop_malloc();
	struct osl_stmt_builder *stmt_builders = NULL;
	osl_arrays_p arrays = osl_arrays_malloc();
	struct add_access_relation_data ar_data;
	isl_union_map *schedule_map;
	osl_statement_p *stmt_ptr;
	struct osl_stmt_builder *builder;

	osl_generic_add(&scop->extension,
			osl_generic_shell(arrays, osl_arrays_interface()));

	scop->context = osl_relation_from_isl_set(context);
	if (context && !scop->context) {
		WARN("could not convert context");
		osl_scop_free(scop);
		return NULL;
	}
	osl_relation_set_type(scop->context, OSL_TYPE_CONTEXT);

	if (isl_union_set_foreach_set(domain, &add_osl_stmt_builder_to_list,
				      &stmt_builders) != isl_stat_ok) {
		WARN("could not convert domains");
		free_stmt_builder(stmt_builders);
		osl_scop_free(scop);
		return NULL;
	}

	ar_data.arrays = arrays;
	ar_data.builders = stmt_builders;
	ar_data.type = OSL_TYPE_READ;
	if (isl_union_map_foreach_map(reads, &add_access_relation_to_list,
				      &ar_data) != isl_stat_ok) {
		WARN("could not convert reads");
		free_stmt_builder(stmt_builders);
		osl_scop_free(scop);
		return NULL;
	}
	ar_data.type = OSL_TYPE_WRITE;
	if (isl_union_map_foreach_map(writes, &add_access_relation_to_list,
				      &ar_data) != isl_stat_ok) {
		WARN("could not convert writes");
		free_stmt_builder(stmt_builders);
		osl_scop_free(scop);
		return NULL;
	}

	schedule_map = isl_schedule_get_map(schedule);
	if (isl_union_map_foreach_map(schedule_map, &add_schedule,
				      stmt_builders) != isl_stat_ok) {
		WARN("could not convert schedule");
		free_stmt_builder(stmt_builders);
		osl_scop_free(scop);
		return NULL;
	}

	stmt_ptr = &scop->statement;
	for (builder = stmt_builders; builder != NULL;
	     builder = builder->next) {
		*stmt_ptr = builder->stmt;
		builder->stmt = NULL;
		stmt_ptr = &(*stmt_ptr)->next;
	}

	free_stmt_builder(stmt_builders);
	return scop;
}

