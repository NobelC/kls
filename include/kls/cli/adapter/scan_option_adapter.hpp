#pragma once 
#include "../model/parser_options.hpp"
#include "../../scanner/scanner.hpp"

namespace kls::cli::adapter {
  [[nodiscard]] scanner::ScanOptions to_scan_options(const model::ParsedOptions& opts);
}
