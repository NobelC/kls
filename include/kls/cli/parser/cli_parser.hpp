#pragma once 
#include "../model/parserd_option.hpp"
#include "../model/cli_error.hpp"
#include "../../result.hpp"
#include <string_view>
#include <span>

namespace kls::cli::parser {
  using ArgvView = std::span<const std::string_view>;
  using ParseResult = kls::Result<model::ParsedOptions,model::CliError>;
  [[nodiscard]] ParseResult parse(ArgvView argv);
}
