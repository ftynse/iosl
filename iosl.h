#ifndef IOSL_H
#define IOSL_H

#include <isl/map.h>
#include <isl/set.h>
#include <isl/union_map.h>
#include <isl/union_set.h>
#include <isl/schedule.h>

#include <osl/osl.h>

osl_relation_p osl_relation_from_isl_basic_set(__isl_take isl_basic_set *);
osl_relation_p osl_relation_from_isl_basic_map(__isl_take isl_basic_map *);
osl_relation_p osl_relation_from_isl_set(__isl_take isl_set *);
osl_relation_p osl_relation_from_isl_map(__isl_take isl_map *);

osl_scop_p osl_scop_from_isl(__isl_take isl_set *context,
                             __isl_take isl_union_set *domain,
                             __isl_take isl_union_map *reads,
                             __isl_take isl_union_map *writes,
                             __isl_take isl_schedule *schedule);

#endif
