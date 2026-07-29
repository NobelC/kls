#include "capabilities-register.hpp"
#include <cstdint>
#include <sys/types.h>
#include <unordered_map>

static std::unordered_map<uint32_t,kls::findings::Finding> table_capability_flag;

void GeneralCapabilityLog(const kls::findings::Finding& health){
  table_capability_flag.insert_or_assign(health.id.get_value(), health);
}

const kls::findings::Finding* GetCapabilityFlag(const ID& id){
  auto its = table_capability_flag.find(id.get_value());
  if(its == table_capability_flag.end()){
    return nullptr;
  }
  return &its->second;
}

