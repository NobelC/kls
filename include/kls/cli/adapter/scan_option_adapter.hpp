#pragma once 
#include "kls/cli/model/parser_options.hpp"
#include "kls/scanner/scanner.hpp"

namespace kls::cli::adapter {
  [[nodiscard]] scanner::ScanOptions to_scan_options(const model::ParsedOptions& opts);
}
