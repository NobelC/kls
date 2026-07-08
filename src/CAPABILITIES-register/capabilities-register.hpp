#pragma once
#include "../../include/kls/findings/health_flags.hpp"
#include "../../include/kls/detail/Id.hpp"

void GeneralCapabilityLog(const kls::findings::HealthFlags& health);
void PrintCapabilityFlags(const ID& id);
const kls::findings::HealthFlags* GetCapabilityFlag(const ID& id);
void CreatedCapabilityFlags();
