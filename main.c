#include "iosl.h"

#include <pet.h>
#include <isl/ctx.h>

void read_scop(FILE *f)
{
	osl_scop_p scop = osl_scop_read(f);
	isl_ctx *ctx = isl_ctx_alloc();

	isl_set *context;
	isl_union_set *domain;
	isl_union_map *reads, *writes;
	isl_schedule *schedule;

	isl_from_osl_scop(ctx, scop, &context, &domain, &reads, &writes,
			  &schedule);

	isl_set_dump(context);
	isl_union_set_dump(domain);
	isl_union_map_dump(reads);
	isl_union_map_dump(writes);
	isl_schedule_dump(schedule);

	isl_set_free(context);
	isl_union_set_free(domain);
	isl_union_map_free(reads);
	isl_union_map_free(writes);
	isl_schedule_free(schedule);

	isl_ctx_free(ctx);
}

void read_code(const char *filename)
{
	int i;
	isl_ctx *ctx = isl_ctx_alloc_with_pet_options();
	pet_scop *scop = pet_scop_extract_from_C_source(ctx, filename, NULL);
	isl_set *context = pet_scop_get_context(scop);
	isl_union_map *reads = pet_scop_get_may_reads(scop);
	isl_union_map *writes = pet_scop_get_may_writes(scop);
	isl_schedule *schedule = pet_scop_get_schedule(scop);
	isl_union_set *domain = isl_union_set_empty(isl_set_get_space(context));

	for (i = 0; i < scop->n_stmt; ++i) {
		domain = isl_union_set_add_set(domain,
					isl_set_copy(scop->stmts[i]->domain));
	}

	reads = isl_union_map_gist_domain(reads, isl_union_set_copy(domain));
	writes = isl_union_map_gist_domain(writes, isl_union_set_copy(domain));

	osl_scop_p osl_scop =
		osl_scop_from_isl(context, domain, reads, writes, schedule);
	osl_scop->language = "C";

	osl_scop_print(stdout, osl_scop);
}

int main(int argc, char *argv[])
{
	FILE *f = fopen(argv[1], "r");
	read_scop(f);
	read_code(argv[2]);

	return 0;
}
