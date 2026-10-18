#include "kls/audit/audit_orchestrator.hpp"
#include "kls/analyzers/analyze_entries.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include <utility>
#include <variant>

namespace kls::auditor {

// ARCHITECTURAL NOTE: Strict pipeline enforcement.
// The orchestrator guarantees that security analysis only runs if the 
// initial filesystem scan succeeds. This prevents analyzers from operating 
// on invalid or incomplete state, maintaining clear failure semantics.
[[nodiscard]] kls::scanner::ScanResult audit_orchestrator(
    const std::string& root, 
    const kls::scanner::ScanOptions& options
) {
  auto scan_result = kls::scanner::orchestrator(root, options);

  // Fail-fast: If the root cannot be scanned, abort immediately.
  // Do not attempt analysis on a fundamentally broken scan state.
  if (auto* failure = std::get_if<kls::Failure<kls::scanner::ScanError>>(&scan_result)) {
    return kls::scanner::ScanResult{
        kls::Failure<kls::scanner::ScanError>{std::move(failure->error)}
    };
  }

  auto& success = std::get<kls::Success<kls::scanner::ScanOutput>>(scan_result);
  
  // ARCHITECTURAL NOTE: Zero-copy state transition.
  // std::move transfers ownership of the heavy ScanOutput to the analyzer.
  // This avoids expensive deep copies of vectors containing thousands of entries.
  auto analyzed_entries = analyzer::analyze_entries(std::move(success.value), options);
  
  return kls::scanner::ScanResult{
      kls::Success<kls::scanner::ScanOutput>{std::move(analyzed_entries)}
  };
}

} // namespace kls::auditor
