#pragma once 
#include "kls/cli/model/parser_options.hpp"
#include "kls/cli/model/cli_error.hpp"
#include "kls/result.hpp"
#include <string_view>
#include <span>

namespace kls::cli::parser {
  using ArgvView = std::span<const std::string_view>;
  using ParseResult = kls::Result<model::ParsedOptions,model::CliError>;
  [[nodiscard]] ParseResult parse(ArgvView argv);
}
