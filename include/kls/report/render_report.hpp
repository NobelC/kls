#pragma once
#include "../audit/audit_entry.hpp"
#include "../report/render_option.hpp"
#include <ostream>
#include <span>

namespace kls::report{
void render_report(
    std::ostream& output,
    std::span<const kls::audit::AuditEntry> entries,
    const RenderOptions& options
);
}
