#pragma once
#include <kls/audit/audit_entry.hpp>
#include <ostream>
#include <span>

namespace kls::report{
  void render_report(std::ostream output,std::span<const kls::audit::AuditEntry> entries, const Option& option_bool)noexcept;
}
