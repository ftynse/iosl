#include "iosl.h"

#include <isl/map.h>
#include <isl/set.h>
#include <isl/union_map.h>
#include <isl/union_set.h>
#include <isl/schedule.h>
#include <isl/printer.h>
#include <isl/id.h>
#include <isl/constraint.h>
#include <isl/aff.h>

#include <osl/osl.h>

#include <limits.h>

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

//============================================================================//

__isl_give isl_basic_map *isl_basic_map_from_osl_relation_single(
		isl_ctx *ctx, osl_relation_p relation) {
	isl_basic_map *bmap;
	osl_relation_p next = relation->next;
	relation->next = NULL;
	char *string = osl_relation_spprint_polylib(relation, NULL);
	relation->next = next;
	bmap = isl_basic_map_read_from_str(ctx, string);
	free(string);
	return bmap;
}

__isl_give isl_union_map *isl_union_map_from_osl_relation(
		isl_ctx *ctx, osl_relation_p relation) {
	isl_basic_map *bmap;
	isl_union_map *umap = NULL;

	for ( ; relation != NULL; relation = relation->next) {
		bmap = isl_basic_map_from_osl_relation_single(ctx, relation);
		if (!umap)
			umap = isl_union_map_from_basic_map(bmap);
		else
			umap = isl_union_map_union(umap,
					isl_union_map_from_basic_map(bmap));
	}
	return umap;
}

__isl_give isl_map *isl_map_from_osl_relation(isl_ctx *ctx,
					      osl_relation_p relation)
{
	isl_union_map *umap = isl_union_map_from_osl_relation(ctx, relation);
	if (isl_union_map_n_map(umap) != 1) {
		WARN("the relation is not a (single) map");
		isl_union_map_free(umap);
		return NULL;
	}
	return isl_map_from_union_map(umap);
}

__isl_give isl_map *isl_map_copy_param_names(
	__isl_take isl_map *map, osl_strings_p names)
{
	int n_param_isl = isl_map_dim(map, isl_dim_param);
	int n_param_osl = osl_strings_size(names);
	int i;
	isl_id *id;
	isl_ctx *ctx = isl_map_get_ctx(map);

	if (n_param_isl != n_param_osl)
		WARN("mismatching parameter sets, copying minimial amount");

	for (i = 0; i < n_param_isl && i < n_param_osl; ++i) {
		id = isl_id_alloc(ctx, names->string[i], NULL);
		map = isl_map_set_dim_id(map, isl_dim_param, i, id);
	}
	return map;
}

struct map_extract_data {
	isl_union_map *result;
	isl_union_map *remaining;
};

static isl_stat map_helper_extract_first(__isl_take isl_map *map, void *user) {
	int n_out;
	isl_map *car, *cdr;
	struct map_extract_data *data = (struct map_extract_data *) user;

	n_out = isl_map_dim(map, isl_dim_out);
	if (n_out == 0)
		return isl_stat_ok;

	car = isl_map_project_out(isl_map_copy(map), isl_dim_out,
				  1, n_out - 1);
	data->result = isl_union_map_union(data->result,
					   isl_union_map_from_map(car));
	if (n_out > 1) {
		cdr = isl_map_project_out(map, isl_dim_out, 0, 1);
		data->remaining = isl_union_map_union(data->remaining,
					isl_union_map_from_map(cdr));
	}
	return isl_stat_ok;
}

static __isl_give isl_union_map *extract_first_dimension(
		__isl_take isl_union_map *umap,
		__isl_give isl_union_map **remaining)
{
	isl_union_map *result = isl_union_map_empty(
					isl_union_map_get_space(umap));
	isl_union_map *rem = isl_union_map_empty(
					isl_union_map_get_space(umap));
	struct map_extract_data data = { result, rem };

	if (isl_union_map_foreach_map(umap, &map_helper_extract_first,
				      &data) != isl_stat_ok) {
		data.result = isl_union_map_free(data.result);
		data.remaining = isl_union_map_free(data.remaining);
	}
	isl_union_map_free(umap);
	if (remaining)
		*remaining = data.remaining;
	else
		isl_union_map_free(data.remaining);
	return data.result;
}

static isl_stat basic_map_helper_first_dimension_scalar(
		__isl_take isl_basic_map *bmap, void *user)
{
	int *pval = (int *) user;
	isl_constraint *c;
	int i, n, num, den, val;
	isl_val *v;

	isl_bool r =
		isl_basic_map_has_defining_equality(bmap, isl_dim_out, 0, &c);
	if (r < 0) {
		*pval = INT_MIN;
		return isl_stat_error;
	}
	if (!r) {
		*pval = INT_MIN;
		return isl_stat_ok;
	}

	n = isl_constraint_dim(c, isl_dim_in);
	for (i = 0; i < n; ++i) {
		v = isl_constraint_get_coefficient_val(c, isl_dim_in, i);
		r = isl_val_is_zero(v);
		isl_val_free(v);
		if (r < 0) {
			isl_constraint_free(c);
			*pval = INT_MIN;
			return isl_stat_error;
		}
		if (!r) {
			isl_constraint_free(c);
			*pval = INT_MIN;
			return isl_stat_ok;
		}
	}
	n = isl_constraint_dim(c, isl_dim_param);
	for (i = 0; i < n; ++i) {
		v = isl_constraint_get_coefficient_val(c, isl_dim_param, i);
		r = isl_val_is_zero(v);
		isl_val_free(v);
		if (r < 0) {
			isl_constraint_free(c);
			*pval = INT_MIN;
			return isl_stat_error;
		}
		if (!r) {
			isl_constraint_free(c);
			*pval = INT_MIN;
			return isl_stat_ok;
		}
	}
	v = isl_constraint_get_constant_val(c);
	num = -isl_val_get_num_si(v);
	den = isl_val_get_den_si(v);
	isl_val_free(v);
	isl_constraint_free(c);
	if ((num % den) != 0) {
		*pval = INT_MIN;
		return isl_stat_ok;
	}
	if (*pval == INT_MAX) {
		*pval = num / den;
	} else if (*pval != num / den) {
		*pval = INT_MIN;
		return isl_stat_error;
	}

	return isl_stat_ok;
}

static isl_stat map_helper_first_dimension_scalar(__isl_take isl_map *map,
						  void *user)
{
	int *pval = (int *) user;
	int const_value = INT_MAX;
	if (isl_map_foreach_basic_map(map,
			&basic_map_helper_first_dimension_scalar,
			&const_value) < 0) {
		isl_map_free(map);
		return isl_stat_error;
	}
	isl_map_free(map);
	*pval = const_value;

	return isl_stat_ok;
}

static isl_bool is_first_dimension_scalar(__isl_keep isl_union_map *umap)
{
	int value;
	if (isl_union_map_foreach_map(umap,
			&map_helper_first_dimension_scalar, &value) < 0)
		return isl_bool_error;
	if (value == INT_MIN)
		return isl_bool_false;
	return isl_bool_true;

}

struct id_rank_list_node {
	isl_id *id;
	int value;
	struct id_rank_list_node *next;
};

void id_rank_list_free(struct id_rank_list_node *list_head) {
	if (!list_head)
		return;

	isl_id_free(list_head->id);
	id_rank_list_free(list_head->next);
	free(list_head);
}

static isl_stat id_rank_list_fill(__isl_take isl_map *map, void *user)
{
	struct id_rank_list_node **list_head =
			(struct id_rank_list_node **) user;
	struct id_rank_list_node *list_node;
	isl_id *id = isl_map_get_tuple_id(map, isl_dim_in);
	int value;

	if (map_helper_first_dimension_scalar(map, &value) < 0)
		return isl_stat_error;

	list_node = (struct id_rank_list_node *) malloc(
				sizeof(struct id_rank_list_node));
	list_node->id = id;
	list_node->value = value;
	list_node->next = NULL;

	if (*list_head)
		list_node->next = *list_head;
	*list_head = list_node;
	return isl_stat_ok;
}

static int id_rank_list_get_value(struct id_rank_list_node *list_head,
				  __isl_keep isl_id *id)
{
	struct id_rank_list_node *it;
	for (it = list_head; it != NULL; it = it->next) {
		if (it->id == id)
			return it->value;
	}
	return INT_MIN;
}

static int id_list_ranked_cmp(__isl_keep isl_id *id1, __isl_keep isl_id *id2,
			      void *user)
{
	struct id_rank_list_node *list_head = (struct id_rank_list_node *) user;
	struct id_rank_list_node *it;
	int value1 = INT_MIN, value2 = INT_MIN;

	for (it = list_head; it != NULL; it = it->next) {
		if (it->id == id1)
			value1 = it->value;
		if (it->id == id2)
			value2 = it->value;
		if (value1 != INT_MIN && value2 != INT_MIN)
			break;
	}
	return value1 - value2;
}

struct map_tuple_has_id_data {
	isl_id *id;
	isl_map *result;
};

static isl_stat map_input_tuple_has_id(__isl_take isl_map *map, void *user)
{
	struct map_tuple_has_id_data *data =
		(struct map_tuple_has_id_data *) user;
	if (isl_map_get_tuple_id(map, isl_dim_in) == data->id)
		data->result = map;
	else
		isl_map_free(map);
	return isl_stat_ok;
}

static __isl_give isl_map *union_map_match_input_tuple_id(
		__isl_keep isl_union_map *umap, __isl_keep isl_id *id)
{
	struct map_tuple_has_id_data data = { id, NULL };
	if (isl_union_map_foreach_map(umap, &map_input_tuple_has_id,
				      &data) < 0)
		return NULL;
	return data.result;
}

static __isl_give isl_schedule *construct_schedule(
	__isl_take isl_union_map *schedule_map,
	__isl_take isl_union_set *domain);

static __isl_give isl_schedule *construct_schedule_sequence(
	__isl_take isl_union_map *current_dim,
	__isl_take isl_union_map *remainder,
	__isl_take isl_union_set *domain)
{
	struct id_rank_list_node *list_head = NULL, *it;
	isl_id_list *id_list;
	isl_ctx *ctx = isl_union_map_get_ctx(current_dim);
	int i, n;
	isl_id *id;
	int previous_value, has_previous_value, value;
	isl_union_set_list *sorted_domain_filters;
	isl_union_set *domain_filter = NULL;
	isl_map *map;
	isl_union_set *partial_domain;
	isl_schedule *schedule;
	isl_union_map *rem;

	isl_union_map_foreach_map(current_dim, &id_rank_list_fill, &list_head);

	id_list = isl_id_list_alloc(ctx, isl_union_map_n_map(current_dim));
	for (it = list_head; it != NULL; it = it->next) {
		id_list = isl_id_list_add(id_list, it->id);
	}
	id_list = isl_id_list_sort(id_list, &id_list_ranked_cmp, list_head);

	sorted_domain_filters = isl_union_set_list_alloc(ctx, 1);
	has_previous_value = 0;
	n = isl_id_list_n_id(id_list);

	if (n == 0) {
		isl_union_map_free(remainder);
		isl_union_map_free(current_dim);
		return isl_schedule_from_domain(domain);
	}

	for (i = 0; i < n; ++i) {
		id = isl_id_list_get_id(id_list, i);
		value = id_rank_list_get_value(list_head, id);
		if (has_previous_value && previous_value == value) {
		} else {
			if (domain_filter)
				sorted_domain_filters = isl_union_set_list_add(
					sorted_domain_filters, domain_filter);
			domain_filter = isl_union_set_empty(
				isl_union_map_get_space(current_dim));
		}
		map = union_map_match_input_tuple_id(current_dim, id);
		domain_filter = isl_union_set_union(domain_filter,
			isl_union_set_from_set(isl_map_domain(map)));

		previous_value = value;
		has_previous_value = 1;
	}
	sorted_domain_filters = isl_union_set_list_add(sorted_domain_filters,
						       domain_filter);

	isl_id_list_free(id_list);
	id_rank_list_free(list_head);

	n = isl_union_set_list_n_union_set(sorted_domain_filters);
	partial_domain = isl_union_set_list_get_union_set(
				sorted_domain_filters, 0);
	partial_domain = isl_union_set_intersect(partial_domain,
						 isl_union_set_copy(domain));
	rem = isl_union_map_intersect_domain(isl_union_map_copy(remainder),
					     isl_union_set_copy(domain));
	schedule = construct_schedule(rem, partial_domain);
	for (i = 1; i < n; ++i) {
		partial_domain =
			isl_union_set_list_get_union_set(sorted_domain_filters,
							 i);
		partial_domain = isl_union_set_intersect(
			isl_union_set_copy(domain), partial_domain);

		rem = isl_union_map_intersect_domain(
				isl_union_map_copy(remainder),
				isl_union_set_copy(domain));
		schedule = isl_schedule_sequence(schedule,
				construct_schedule(rem, partial_domain));
	}
	isl_union_map_free(remainder);
	isl_union_map_free(current_dim);
	isl_union_set_free(domain);
	return schedule;
}

static __isl_give isl_schedule *construct_schedule(
	__isl_take isl_union_map *schedule_map,
	__isl_take isl_union_set *domain)
{
	isl_union_map *current_dim, *remainder;

	schedule_map = isl_union_map_intersect_domain(schedule_map,
						isl_union_set_copy(domain));

	if (!schedule_map ||
	    isl_union_map_is_empty(schedule_map) == isl_bool_true) {
		isl_union_map_free(schedule_map);
		return isl_schedule_from_domain(domain);
	}

	current_dim = extract_first_dimension(schedule_map, &remainder);

	if (!current_dim)
		return NULL;

	if (is_first_dimension_scalar(current_dim) == isl_bool_true) {
		return construct_schedule_sequence(current_dim, remainder, domain);
	} else {
		isl_union_set *partial_domain = isl_union_map_domain(
			isl_union_map_copy(current_dim));
		partial_domain = isl_union_set_intersect(partial_domain,
					isl_union_set_copy(domain));
		current_dim = isl_union_map_gist_domain(current_dim,
					isl_union_set_copy(partial_domain));
		isl_multi_union_pw_aff *mupa =
			isl_multi_union_pw_aff_from_union_map(current_dim);
		isl_schedule *partial_schedule =
				construct_schedule(remainder, partial_domain);
		partial_schedule = isl_schedule_insert_partial_schedule(
			partial_schedule, mupa);
		return partial_schedule;
	}

}

__isl_give isl_schedule *schedule_from_scop(isl_ctx *ctx, osl_scop_p scop,
					    __isl_give isl_set **pcontext,
					    __isl_give isl_union_set **pdomain)
{
	isl_set *context;
	isl_union_set *domain;
	isl_union_map *schedule_map;
	isl_map *context_map;
	osl_statement_p stmt;
	isl_space *space;
	int cnt = 1;
	osl_strings_p param_names;
	isl_schedule *schedule;

	param_names = (osl_strings_p) osl_generic_lookup(scop->parameters,
							   OSL_URI_STRINGS);
	context_map = isl_map_from_osl_relation(ctx, scop->context);
	context_map = isl_map_copy_param_names(context_map, param_names);
	context = isl_map_domain(context_map);

	space = isl_set_get_space(context);
	space = isl_space_params(space);
	domain = isl_union_set_empty(isl_space_copy(space));
	schedule_map = isl_union_map_empty(space);

	for (stmt = scop->statement; stmt != NULL; stmt = stmt->next) {
		isl_map *domain_map;
		isl_map *partial_schedule_map;
		isl_set *domain_set;
		isl_id *id;
		char name[40];

		domain_map = isl_map_from_osl_relation(ctx, stmt->domain);
		domain_map = isl_map_copy_param_names(domain_map, param_names);
		domain_set = isl_map_range(domain_map);
		snprintf(name, 40, "S%d", cnt);
		domain_set = isl_set_set_tuple_name(domain_set, name);

		partial_schedule_map =
			isl_map_from_osl_relation(ctx, stmt->scattering);
		partial_schedule_map = isl_map_copy_param_names(
			partial_schedule_map, param_names);
		partial_schedule_map = isl_map_set_tuple_name(
			partial_schedule_map, isl_dim_in, name);

		domain = isl_union_set_add_set(domain, domain_set);
		schedule_map = isl_union_map_add_map(schedule_map,
						     partial_schedule_map);
		++cnt;
	}

	if (pcontext)
		*pcontext = isl_set_copy(context);

	if (pdomain)
		*pdomain = isl_union_set_copy(domain);

	schedule = construct_schedule(schedule_map, domain);
	schedule = isl_schedule_insert_context(schedule, context);
	return schedule;
}

void collect_accesses(isl_ctx *ctx, osl_scop_p scop,
		      __isl_give isl_union_map **preads,
		      __isl_give isl_union_map **pwrites)
{
	osl_statement_p stmt;
	osl_relation_list_p acc;
	isl_union_map *umap, *array_id_umap, *access_umap;
	isl_map *array_id_map, *access_map;
	int array_id, idx;
	osl_arrays_p arrays;
	osl_strings_p param_names;
	isl_space *space;
	int n_param, i;
	isl_union_map *reads, *writes;
	int cnt = 1;
	isl_map *map;

	arrays = (osl_arrays_p) osl_generic_lookup(scop->extension,
						   OSL_URI_ARRAYS);
	if (!arrays) {
		WARN("no array extension found");
		return;
	}

	param_names = (osl_strings_p) osl_generic_lookup(scop->parameters,
							 OSL_URI_STRINGS);
	if (!param_names) {
		WARN("no parameter names given");
		return;
	}

	n_param = osl_strings_size(param_names);
	space = isl_space_params_alloc(ctx, n_param);
	for (i = 0; i < n_param; ++i) {
		space = isl_space_set_dim_name(space, isl_dim_param, i,
					       param_names->string[i]);
	}
	reads = isl_union_map_empty(isl_space_copy(space));
	writes = isl_union_map_empty(space);

	for (stmt = scop->statement; stmt != NULL; stmt = stmt->next) {
		char stmt_name[40];
		snprintf(stmt_name, 40, "S%d", cnt);

		for (acc = stmt->access; acc != NULL; acc = acc->next) {
			umap = isl_union_map_from_osl_relation(ctx, acc->elt);
			map = isl_map_from_union_map(
						isl_union_map_copy(umap));
			if (isl_map_dim(map, isl_dim_out) == 1) {
				if (map_helper_first_dimension_scalar(map,
						&array_id) < 0) {
					WARN("access relation does not have "
					     "array ID");
					return;
				}
				access_map = isl_map_project_out(
					map, isl_dim_out, 0, 1);
			} else {
				isl_map_free(map);
				array_id_umap =	extract_first_dimension(
							umap, &access_umap);
				array_id_map = isl_map_from_union_map(
							array_id_umap);
				access_map = isl_map_from_union_map(
							access_umap);
				if (!array_id_map || !access_map) {
					WARN("could not extract "
					     "access relations");
					return;
				}
				if (map_helper_first_dimension_scalar(
					    array_id_map, &array_id) < 0) {
					WARN("access relation does not have "
					     "array ID");
					return;
				}
			}
			idx = osl_arrays_get_index_from_id(arrays, array_id);
			if (idx == arrays->nb_names) {
				WARN("array ID is not found");
			}
			access_map = isl_map_set_tuple_name(access_map,
					isl_dim_out, arrays->names[idx]);
			access_map = isl_map_set_tuple_name(access_map,
					isl_dim_in, stmt_name);
			access_map = isl_map_copy_param_names(access_map,
					param_names);

			if (acc->elt->type == OSL_TYPE_READ) {
				reads = isl_union_map_add_map(reads,
							      access_map);
			} else if (acc->elt->type == OSL_TYPE_WRITE) {
				writes = isl_union_map_add_map(writes,
							       access_map);
			} else {
				WARN("unknown access relation type");
				isl_map_free(access_map);
			}
		}
		++cnt;
	}

	if (preads)
		*preads = reads;
	else
		isl_union_map_free(reads);
	if (pwrites)
		*pwrites = writes;
	else
		isl_union_map_free(writes);
}

void isl_from_osl_scop(isl_ctx *ctx, osl_scop_p scop,
		       __isl_give isl_set **context,
		       __isl_give isl_union_set **domain,
		       __isl_give isl_union_map **reads,
		       __isl_give isl_union_map **writes,
		       __isl_give isl_schedule **schedule)
{
	isl_schedule *sched = schedule_from_scop(ctx, scop, context, domain);
	if (schedule)
		*schedule = sched;
	else
		isl_schedule_free(sched);
	collect_accesses(ctx, scop, reads, writes);
}
