#pragma once
#include "kls/scanner/scanner.hpp"


namespace kls::analyzer{
  [[nodiscard]] kls::scanner::ScanOutput analyze_entries(kls::scanner::ScanOutput scan_output,const kls::scanner::ScanOptions& options);
}
