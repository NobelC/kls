#pragma once
#include "../audit/audit_entry.hpp"
#include <string_view>
#include <sys/stat.h>

namespace kls::analyzer{
  void analyze_health(kls::audit::AuditEntry &fe, std::string_view full_path, const struct statx &stx,const time_t& TIME_NOW);
}
