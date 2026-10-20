#pragma once
#include "kls/audit/coverage_report.hpp"
#include "kls/report/render_option.hpp"
#include <ostream>
namespace kls::report{
  void render_coverage(std::ostream& out, const kls::audit::CoverageReport& report, const RenderOptions& opts);
}
