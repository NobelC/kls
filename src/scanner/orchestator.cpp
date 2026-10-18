#include "kls/scanner/scanner.hpp"
#include "kls/result.hpp"
#include "kls/scanner/collect_metadata.hpp"
#include <utility>
#include <variant>

namespace kls::scanner {

// ARCHITECTURAL NOTE: Separation of concerns and fail-fast execution.
// Directory discovery (readdir) is fast and cheap, while metadata collection (statx) 
// is expensive due to syscall overhead. This orchestrator ensures we abort immediately 
// if the root cannot be accessed, preventing wasted syscalls on a doomed traversal.
[[nodiscard]] kls::scanner::ScanResult orchestrator(const std::string& root, const kls::scanner::ScanOptions& options) {
  DiscoveryResult discovery_result = discover_entries(root, options);

  if (auto* failure = std::get_if<kls::Failure<ScanError>>(&discovery_result)) {
    return ScanResult{
        kls::Failure<ScanError>{std::move(failure->error)}
    };
  }

  auto& success = std::get<kls::Success<DiscoveredOutput>>(discovery_result);
  
  // ARCHITECTURAL NOTE: Move semantics.
  // DiscoveredOutput can contain large vectors of paths and candidates. 
  // std::move transfers ownership to collect_metadata, avoiding expensive deep copies.
  return ScanResult{
      kls::Success<ScanOutput>{collect_metadata(std::move(success.value))}
  };
}

} // namespace kls::scanner
