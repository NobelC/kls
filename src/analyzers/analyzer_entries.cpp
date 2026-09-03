#include "kls/analyzers/analyze_entries.hpp"
#include "kls/analyzers/capability_analyzer.hpp"
#include "kls/analyzers/health_analyzer.hpp"


namespace kls::analyzer {

kls::scanner::ScanOutput analyze_entries(
    kls::scanner::ScanOutput scan_output,
    const kls::scanner::ScanOptions& options
) {
    const auto TIME_NOW = time(nullptr);

    if (options.analyze_capabilities || options.analyze_health) {
        
        for (auto& item : scan_output.items) {
            
            if (options.analyze_health) {
                auto health_result = analyze_health(item.entry, TIME_NOW);
                if (!health_result.empty()) {
                    item.findings.insert(
                        item.findings.end(),
                        std::make_move_iterator(health_result.begin()),
                        std::make_move_iterator(health_result.end())
                    );
                }
            }

            if (options.analyze_capabilities) {
                auto cap_result = analyze_capability(item.entry);
                if (!cap_result.empty()) {
                    item.findings.insert(
                        item.findings.end(),
                        std::make_move_iterator(cap_result.begin()),
                        std::make_move_iterator(cap_result.end())
                    );
                }
            }
        }
    }

    return scan_output;
}

} // namespace kls::analyzer
