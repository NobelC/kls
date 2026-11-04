#include "kls/cli/adapter/scan_option_adapter.hpp"
#include "kls/scanner/scanner.hpp"
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <linux/limits.h>
#include <unistd.h>

namespace kls::cli::adapter {

template <std::size_t size>
inline std::string ToString(std::array<char, size> &input) {
  const auto &safeLength = strlen(input.data());
  return std::string(input.data(), safeLength);
}

// ARCHITECTURAL NOTE: Anti-Corruption Layer.
// Translates CLI-specific flags into domain-agnostic scanner configuration.
// This isolates the core scanner from CLI parsing details and future option
// changes.
[[nodiscard]] scanner::ScanOptions
to_scan_options(const model::ParsedOptions &opts) {
  scanner::ScanOptions scan_opts;

  scan_opts.recursive = opts.recursive;
  scan_opts.include_hidden = opts.all;

  // Fallback to max depth ensures unbounded recursion when `--depth` is
  // omitted, matching standard recursive traversal behavior while remaining
  // type-safe.
  if (opts.depth.has_value()) {
    scan_opts.maximum_depth = static_cast<std::size_t>(*opts.depth);
  } else {
    scan_opts.maximum_depth = std::numeric_limits<std::size_t>::max();
  }

  // BASELINE DEFAULT: Health and capability analysis are enabled by default.
  // Future CLI flags may expose these as explicit toggles, but the core
  // security audit requires them active until policy configuration is
  // implemented.
  scan_opts.analyze_capabilities = true;
  scan_opts.analyze_health = true;

  scan_opts.symlink_status = scanner::SymlinkMode::read;
  if (opts.target_path == ".") {
    std::array<char, PATH_MAX> cwd;
    scan_opts.audit_root = getcwd(cwd.data(), cwd.size()) ? ToString(cwd) : ".";
  } else {
    scan_opts.audit_root = opts.target_path;
  }

  // TODO: Map symlink policy from CLI once `--follow-symlinks` or similar
  // flag is stabilized in the declarative spec. Default remains `ignore` in
  // ScanOptions. scan_opts.symlink_status = scanner::SymlinkMode::ignore;

  return scan_opts;
}

} // namespace kls::cli::adapter
