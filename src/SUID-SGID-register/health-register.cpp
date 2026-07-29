#include "health-register.hpp"
#include <cstdint>
#include <sys/types.h>
#include <unordered_map>

static std::unordered_map<uint32_t,kls::findings::Finding> table_health_flag;

void GeneralHealthFlagsLog(const kls::findings::Finding& health){
  table_health_flag.insert_or_assign(health.id.get_value(), health);
}

const kls::findings::Finding* GetHealthFlag(const ID& id){
  auto its = table_health_flag.find(id.get_value());
  if(its == table_health_flag.end()){
    return nullptr;
  }
  return &its->second;
}

