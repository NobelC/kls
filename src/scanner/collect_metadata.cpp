#include "kls/scanner/collect_metadata.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include <utility>
#include <variant>

namespace kls::scanner {

[[nodiscard]] kls::scanner::ScanResult
orchestrator(const std::string &root,
             const kls::scanner::ScanOptions &options) {
  DiscoveryResult discovery_result = discover_entries(root, options);

  if (auto *failure = std::get_if<kls::Failure<ScanError>>(&discovery_result)) {
    return ScanResult{kls::Failure<ScanError>{std::move(failure->error)}};
  }

  // collect_metadata is now the single owner of ScanOutput
  // construction, including propagation of discovery-phase issues and
  // traversal counters. No additional merging needed here.
  auto &success = std::get<kls::Success<DiscoveredOutput>>(discovery_result);
  auto collected = collect_metadata(success.value);

  return ScanResult{
      kls::Success<kls::scanner::ScanOutput>{std::move(collected)}};
}

} // namespace kls::scanner
