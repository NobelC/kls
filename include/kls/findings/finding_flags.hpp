#pragma once
#include "../detail/Id.hpp"
#include <cstdint>
#include <vector>

namespace kls::findings{
  enum class CategoryFindings : uint8_t{
    health,
    capabilities,
  };
  
  enum class SeverityFindings : uint8_t{
    None = 0,
    Low = 1,
    MedLow = 2,
    Med = 3,
    High = 4,
    Crit = 5,
  };

  struct Finding {
      const char* message = nullptr;
      ID id;
      SeverityFindings level = SeverityFindings::None;
      CategoryFindings type_findings = CategoryFindings::health;
  };

  struct FindingCollection{
    size_t ID_path = 0;
    std::vector<ID> id_finding;
  };
}
