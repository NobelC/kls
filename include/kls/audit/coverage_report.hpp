#pragma once 
#include <cstddef>

namespace kls::audit {
  struct CoverageReport{
    std::size_t visited = 0;
    std::size_t discovered = 0;
    std::size_t inspected = 0;
    
    std::size_t denied = 0 ;
    std::size_t disappeared = 0;
    std::size_t unstable = 0;
    std::size_t unsupported = 0;
    std::size_t excluded = 0;
    std::size_t limits_reached = 0;

    [[nodiscard]] double calculate_effective_coverage() const{
      const std::size_t total_evaluable = inspected + denied + disappeared + unstable + unsupported;
      if(total_evaluable == 0){
        return 100.0;
      }
      return (static_cast<double>(inspected) / static_cast<double>(total_evaluable)) *  100.0;
    }

  };
}
