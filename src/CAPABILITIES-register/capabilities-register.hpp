#pragma once
#include "option/option-raw-metadata.hpp"

void GeneralCapabilityLog(const HealthFlag& health);
void PrintCapabilityFlags(const ID& id);
const HealthFlag* GetCapabilityFlag(const ID& id);
void CreatedCapabilityFlags();
