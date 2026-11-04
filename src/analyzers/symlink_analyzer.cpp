#include "kls/analyzers/symlink_analyzer.hpp"
#include <cerrno>
#include <sys/stat.h>

namespace kls::analyzer {

[[nodiscard]] std::vector<kls::detail::ID>
analyze_symlink(const kls::auditor::AuditEntry &fe,
                const std::string &audit_root) {

  std::vector<kls::detail::ID> findings;

  // Only evaluate actual symlinks with a known target.
  if (fe.type != filesystem::FileType::symlink ||
      !fe.symlink_target.has_value()) {
    return findings;
  }

  const std::string &target = *fe.symlink_target;

  // 1. Detect Escape (SY03)
  // If the target is an absolute path and does not start with the audit root,
  // it points outside the authorized boundary.
  if (!target.empty() && target[0] == '/') {
    std::string safe_root = audit_root;
    if (!safe_root.empty() && safe_root.back() != '/') {
      safe_root.push_back('/');
    }
    // Check if target is exactly the root or a subpath of it
    if (target != safe_root && !target.starts_with(safe_root)) {
      findings.emplace_back("SY03");
    }
  }

  // 2. Detect Broken (SY01) and Loops (SY02)
  // We use ::stat (without O_NOFOLLOW) on the symlink's full_path.
  // The kernel will attempt to resolve the target.
  struct stat st;
  if (::stat(fe.full_path.c_str(), &st) == -1) {
    if (errno == ENOENT) {
      findings.emplace_back("SY01"); // Target does not exist
    } else if (errno == ELOOP) {
      findings.emplace_back("SY02"); // Resolution exceeded MAXSYMLINKS
    }
  }

  return findings;
}

} // namespace kls::analyzer
