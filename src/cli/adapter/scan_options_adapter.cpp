#include "kls/cli/adapter/scan_option_adapter.hpp"
#include <cstddef>
#include <limits>

namespace kls::cli::adapter {

// ARCHITECTURAL NOTE: Anti-Corruption Layer.
// Translates CLI-specific flags into domain-agnostic scanner configuration.
// This isolates the core scanner from CLI parsing details and future option changes.
[[nodiscard]] scanner::ScanOptions to_scan_options(const model::ParsedOptions& opts) {
  scanner::ScanOptions scan_opts;

  scan_opts.recursive = opts.recursive;
  scan_opts.include_hidden = opts.all;

  // Fallback to max depth ensures unbounded recursion when `--depth` is omitted, 
  // matching standard recursive traversal behavior while remaining type-safe.
  if (opts.depth.has_value()) {
    scan_opts.maximum_depth = static_cast<std::size_t>(*opts.depth);
  } else {
    scan_opts.maximum_depth = std::numeric_limits<std::size_t>::max();
  }

  // BASELINE DEFAULT: Health and capability analysis are enabled by default.
  // Future CLI flags may expose these as explicit toggles, but the core 
  // security audit requires them active until policy configuration is implemented.
  scan_opts.analyze_capabilities = true;
  scan_opts.analyze_health = true;

  // TODO: Map symlink policy from CLI once `--follow-symlinks` or similar 
  // flag is stabilized in the declarative spec. Default remains `ignore` in ScanOptions.
  // scan_opts.symlink_status = scanner::SymlinkMode::ignore;

  return scan_opts;
}

} // namespace kls::cli::adapter
