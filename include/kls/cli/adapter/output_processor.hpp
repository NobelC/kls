#pragma once
#include "kls/cli/model/parser_options.hpp"
#include "kls/scanner/scanner.hpp"

namespace kls::cli::adapter {

void process_output(scanner::ScanOutput& output, const model::ParsedOptions& opts);

} // namespace kls::cli::adapter
