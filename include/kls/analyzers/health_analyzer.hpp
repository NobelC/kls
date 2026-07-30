#pragma once
#include "../audit/audit_entry.hpp"
#include "../detail/Id.hpp"
#include <sys/stat.h>
#include <vector>

namespace kls::analyzer{
std::vector<ID> analyze_health(const kls::auditor::AuditEntry &fe,const time_t& TIME_NOW);
}
