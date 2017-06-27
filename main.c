#include "iosl.h"

#include <pet.h>
#include <isl/ctx.h>

int main(int argc, char *argv[])
{
	int i;
	isl_ctx *ctx = isl_ctx_alloc_with_pet_options();
	pet_scop *scop = pet_scop_extract_from_C_source(ctx, argv[1], NULL);
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

//	osl_scop_dump(stdout, osl_scop);
	osl_scop_print(stdout, osl_scop);

#if 0
	isl_ctx *ctx = isl_ctx_alloc();

	FILE *f = fopen(argv[1],"r");

	isl_schedule *schedule = isl_schedule_read_from_file(ctx, f);
	fclose(f);

	isl_union_map_dump(isl_schedule_get_map(schedule));

	isl_ctx_free(ctx);
#endif
	return 0;
}
