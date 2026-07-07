#pragma once
#include <kls/audit/audit_entry.hpp>
#include <string_view>

namespace kls::analyzer{
  void analyze_capability(kls::audit::AuditEntry &fe, std::string_view full_path) noexcept; 
}
