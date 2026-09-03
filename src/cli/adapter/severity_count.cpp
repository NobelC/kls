#include "kls/cli/adapter/severity_count.hpp"
#include "kls/findings/finding_flags.hpp"
#include "kls/findings/finding_registry.hpp"

namespace kls::cli::adapter{
  [[nodiscard]] SeverityCount count_findings_by_severity(const scanner::ScanOutput &output) noexcept{
    SeverityCount counts;
    for(const auto& item : output.items){
      for(const auto& finding_id : item.findings){
        const auto* finding = findings::get_finding(finding_id);
        if(!finding){continue;}
        
        switch (finding->level) {
          case kls::findings::SeverityFindings::None:
            continue;
            break;
          case kls::findings::SeverityFindings::Low:
            counts.low++;
            break;
          case kls::findings::SeverityFindings::MedLow:
            counts.med_low++;
            break;
          case kls::findings::SeverityFindings::Med:
            counts.med++;
            break;
          case kls::findings::SeverityFindings::Crit:
            counts.crit++;
            break;
          case kls::findings::SeverityFindings::High:
            counts.high++;
            break;
        }
      }
    }
    return counts;
  }
}
