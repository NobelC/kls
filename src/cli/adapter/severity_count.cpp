#include "kls/cli/adapter/severity_count.hpp"
#include "kls/findings/finding_flags.hpp"
#include "kls/findings/finding_registry.hpp"

namespace kls::cli::adapter {

// ARCHITECTURAL NOTE: Separation of concerns.
// Aggregation logic resides in the CLI adapter, keeping the core scanner 
// model pure and focused solely on discovery and metadata collection.
[[nodiscard]] SeverityCount count_findings_by_severity(const scanner::ScanOutput &output) noexcept {
  SeverityCount counts;

  for (const auto& item : output.items) {
    for (const auto& finding_id : item.findings) {
      const auto* finding = findings::get_finding(finding_id);
      
      // Safety check: Ignore unregistered or malformed finding IDs 
      // to prevent null pointer dereferences.
      if (!finding) {
        continue;
      }

      switch (finding->level) {
        case kls::findings::SeverityFindings::None: {
          continue;
        }
        case kls::findings::SeverityFindings::Low: {
          counts.low++;
          break;
        }
        case kls::findings::SeverityFindings::MedLow: {
          counts.med_low++;
          break;
        }
        case kls::findings::SeverityFindings::Med: {
          counts.med++;
          break;
        }
        case kls::findings::SeverityFindings::High: {
          counts.high++;
          break;
        }
        case kls::findings::SeverityFindings::Crit: {
          counts.crit++;
          break;
        }
      }
    }
  }

  return counts;
}

} // namespace kls::cli::adapter
