#pragma once
#include <sys/types.h>
#include "../../include/kls/findings/health_flags.hpp"
#include "../../include/kls/detail/Id.hpp"
 

void GeneralHealthFlagsLog(const kls::findings::HealthFlags& health);
void PrintHealthFlags(const ID& id);
const kls::findings::HealthFlags* GetHealthFlag(const ID& id);
void CreatedHealthFlags();
