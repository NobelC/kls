#include "kls/report/render_coverage.hpp"
#include <iomanip>
#include <iostream>

namespace kls::report{
  void render_coverage(std::ostream& out, const kls::audit::CoverageReport& report, const RenderOptions& opts){
    out << "\n--- Coverage Report ---\n";
    out << "Visited:    " << report.visited << "\n";
    out << "Discovered: " << report.discovered << "\n";
    out << "Inspected:  " << report.inspected << "\n";
    out << "Excluded:   " << report.excluded << "\n";
    out << "Denied:     " << report.denied << "\n";
    out << "Disappeared:" << report.disappeared << "\n";
    out << "Unstable:   " << report.unstable << "\n";
    out << "Unsupported:" << report.unsupported << "\n";
    out << "Limits:     " << report.limits_reached << "\n";
    
    out << "-----------------------\n";
    out << std::fixed << std::setprecision(2);
    out << "Effective Coverage: " << report.calculate_effective_coverage() << "%\n";
  }
}
