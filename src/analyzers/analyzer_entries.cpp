#include "kls/analyzers/analyze_entries.hpp"
#include "kls/analyzers/capability_analyzer.hpp"
#include "kls/analyzers/health_analyzer.hpp"


namespace kls::analyzer{

kls::scanner::ScanOutput analyze_entries(
    kls::scanner::ScanOutput scan_output,
    const kls::scanner::ScanOptions& options
) {
    const auto TIME_NOW = time(nullptr);

    if (options.analyze_health) {
      
        for (auto& item : scan_output.items) {
            auto health_result = analyze_health(item.entry, TIME_NOW);
            if (!health_result.empty()) {
                // Inicializar el optional si es la primera vez
                if (!item.health_findings.has_value()) {
                    item.health_findings.emplace();
                }
                item.health_findings->push_back(std::move(health_result));
            }
        }
    }

    if (options.analyze_capabilities) {
      
        for (auto& item : scan_output.items) {
            auto cap_result = analyze_capability(item.entry);
            if (!cap_result.empty()) {
      
                if (!item.finding_capabilities.has_value()) {
                    item.finding_capabilities.emplace();
                }
                item.finding_capabilities->push_back(std::move(cap_result));
            }
        }
    }

    return scan_output;
}

}
