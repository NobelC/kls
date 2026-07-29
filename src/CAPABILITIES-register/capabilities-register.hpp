#pragma once
#include "../../include/kls/findings/finding_flags.hpp"
#include "../../include/kls/detail/Id.hpp"

void GeneralCapabilityLog(const kls::findings::Finding& health);
void PrintCapabilityFlags(const ID& id);
const kls::findings::Finding* GetCapabilityFlag(const ID& id);
void CreatedCapabilityFlags();
