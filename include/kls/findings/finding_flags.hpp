#pragma once
#include "../detail/Id.hpp"
#include <cstdint>
#include <vector>

namespace kls::findings{
  enum class CategoryFindings : uint8_t{
    health,
    capabilities,
  };

  struct Finding {
      const char* message = nullptr;
      ID id;
      uint8_t level = 0;
      CategoryFindings type_findings = CategoryFindings::health;
  };

  struct FindingCollection{
    size_t ID_path = 0;
    std::vector<ID> id_finding;
  };
}
