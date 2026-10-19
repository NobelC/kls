#include "kls/scanner/scanner.hpp"
#include "kls/result.hpp"
#include "kls/scanner/collect_metadata.hpp"
#include <iterator>
#include <utility>
#include <variant>

namespace kls::scanner {


[[nodiscard]] kls::scanner::ScanResult orchestrator(const std::string& root, const kls::scanner::ScanOptions& options) {
  DiscoveryResult discovery_result = discover_entries(root, options);

  if (auto* failure = std::get_if<kls::Failure<ScanError>>(&discovery_result)) {
    return ScanResult{
        kls::Failure<ScanError>{std::move(failure->error)}
    };
  }

  // ARCHITECTURAL NOTE: Zero-copy read and deferred propagation.
  // collect_metadata reads from DiscoveredOutput by const reference to avoid 
  // copying large vectors (candidates, paths). 
  // The orchestrator, as the owner of discovery_result, then moves the 
  // discovery issues into the final output, ensuring efficient propagation.
  auto& success = std::get<kls::Success<DiscoveredOutput>>(discovery_result);
  auto collected = collect_metadata(success.value);
  if(!success.value.issues.empty()){
    collected.issues.insert(collected.issues.end(),
                            std::make_move_iterator(success.value.issues.begin()),
                            std::make_move_iterator(success.value.issues.end())
    );
    success.value.issues.clear();
  }
   
  return ScanResult{kls::Success<kls::scanner::ScanOutput>{std::move(collected)}};
}

} // namespace kls::scanner
