#pragma once
#include <sys/types.h>
#include "../../include/kls/findings/finding_flags.hpp"
#include "../../include/kls/detail/Id.hpp"
 

void GeneralHealthFlagsLog(const kls::findings::Finding& health);
void PrintHealthFlags(const ID& id);
const kls::findings::Finding* GetHealthFlag(const ID& id);
void CreatedHealthFlags();
