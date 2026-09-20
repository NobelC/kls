#pragma once
#include "kls/scanner/scanner.hpp"
#include "render_option.hpp"
#include <ostream>

namespace kls::report {
void render_report(std::ostream &output,
                   const kls::scanner::ScanOutput &entries,
                   const RenderOptions &options);
}
