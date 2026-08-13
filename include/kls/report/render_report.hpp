#pragma once
#include "kls/report/render_option.hpp"
#include "kls/scanner/scanner.hpp"
#include <ostream>

namespace kls::report{
void render_report(
    std::ostream& output,
    const kls::scanner::ScanOutput& entries,
    const RenderOptions& options
);
}
