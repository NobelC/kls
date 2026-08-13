#pragma once 
#include "kls/cli/model/parser_options.hpp"
#include "kls/report/render_option.hpp"

namespace kls::cli::adapter {
  [[nodiscard]] report::RenderOptions to_render_options(const model::ParsedOptions& opts);
}
