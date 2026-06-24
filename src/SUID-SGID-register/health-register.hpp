#pragma once
#include "option/option-raw-metadata.hpp"
#include <sys/types.h> 

void GeneralHealthFlagsLog(const HealthFlag& health);
void PrintHealthFlags(const ID& id);
const HealthFlag* GetHealthFlag(const ID& id);
void CreatedHealthFlags();
