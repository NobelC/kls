#pragma once 
#include "../detail/Id.hpp"
#include <cstdint>
namespace kls::findings{
  struct HealthFlags{
      const char* message; 
      ID id;
      uint8_t level;
  };
}
