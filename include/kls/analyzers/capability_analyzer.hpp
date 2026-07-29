#pragma once
#include "../audit/audit_entry.hpp"
#include "kls/detail/Id.hpp"
#include <vector>

namespace kls::analyzer{
std::vector<ID> analyze_capability(const kls::audit::AuditEntry &fe); 
}
