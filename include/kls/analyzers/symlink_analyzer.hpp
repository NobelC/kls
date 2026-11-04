#pragma once
#include "kls/audit/audit_entry.hpp"
#include "kls/detail/Id.hpp"
#include <string>
#include <vector>

namespace kls::analyzer {
[[nodiscard]] std::vector<kls::detail::ID>
analyze_symlink(const kls::auditor::AuditEntry &fe,
                const std::string &audit_root);
} // namespace kls::analyzer
