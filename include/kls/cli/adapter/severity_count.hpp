#pragma once 
#include "kls/scanner/scanner.hpp"
#include "kls/findings/finding_flags.hpp"
#include <cstddef>

namespace kls::cli::adapter {
  struct SeverityCount{
    size_t low = 0;
    size_t med_low = 0;
    size_t med = 0;
    size_t high = 0;
    size_t crit = 0;

    [[nodiscard]] size_t at_or_above(findings::SeverityFindings level) const noexcept{
      switch (level) {
      case kls::findings::SeverityFindings::None:
        return 0;   
      case kls::findings::SeverityFindings::Low:
          return low + med_low + high + crit;
      case kls::findings::SeverityFindings::MedLow:
        return med_low + med + high + crit;
      case  kls::findings::SeverityFindings::Med:
        return med + high + crit;
      case kls::findings::SeverityFindings::High:
        return high + crit;
      case kls::findings::SeverityFindings::Crit:
        return crit;
      }
      return 0;
    }
  };
  
  [[nodiscard]] SeverityCount count_findings_by_severity(const scanner::ScanOutput& output) noexcept;
}
