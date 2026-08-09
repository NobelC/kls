#pragma once 
#include "../model/parser_options.hpp"
#include "../model/cli_error.hpp"
#include "../../result.hpp"

namespace kls::cli::validator {
  using ValidationResult = kls::Result<model::ParsedOptions,model::CliError>;
  [[nodiscard]] ValidationResult validate(const model::ParsedOptions& opts);
}
