#pragma once 
#include "kls/cli/model/parser_options.hpp"
#include "kls/cli/model/cli_error.hpp"
#include "kls/result.hpp"

namespace kls::cli::validator {
  using ValidationResult = kls::Result<model::ParsedOptions,model::CliError>;
  [[nodiscard]] ValidationResult validate(const model::ParsedOptions& opts);
}
