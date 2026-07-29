#include "../../include/kls/analyzers/analyze_entries.hpp"
#include "kls/analyzers/capability_analyzer.hpp"
#include "kls/analyzers/health_analyzer.hpp"


namespace kls::analyzer{
  [[nodiscard]] kls::scanner::ScanOutput analyze_entries(kls::scanner::ScanOutput scan_output,const kls::scanner::ScanOptions& options){
    if(options.analyze_health){
      scan_output.health_findings.emplace();
      auto& health_findings = *scan_output.health_findings;
      health_findings.reserve(scan_output.entries.size());
      const time_t current_time = std::time(nullptr);
      for(const auto& entry : scan_output.entries){
        health_findings.emplace_back(analyze_health(entry,current_time));
      }
    }
    
    if(options.analyze_capabilities){
      scan_output.finding_capabilities.emplace();
      auto& finding_capabilities = *scan_output.finding_capabilities;
      finding_capabilities.reserve(scan_output.entries.size());
      for(const auto& entry: scan_output.entries){
        finding_capabilities.emplace_back(analyze_capability(entry));  
      }
    }
    return scan_output;
  }
}
