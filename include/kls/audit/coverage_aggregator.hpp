#pragma once 
#include "kls/audit/coverage_report.hpp"
#include "kls/scanner/scanner.hpp"

namespace kls::audit {
  kls::audit::CoverageReport coverage_aggregator(kls::scanner::ScanOutput& scan_output);
}
