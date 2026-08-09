#pragma once
#include "../audit/audit_entry.hpp"
#include "../detail/Id.hpp"
#include <vector>

namespace kls::analyzer{
std::vector<ID> analyze_capability(const kls::auditor::AuditEntry &fe);
}
