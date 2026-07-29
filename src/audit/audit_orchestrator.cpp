#include "../../include/kls/audit/audit_orchestrator.hpp"
#include "kls/analyzers/analyze_entries.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include <utility>
#include <variant>

namespace kls::auditor {
  [[nodiscard]] kls::scanner::ScanResult audit_orchestrator(const std::string& root, const kls::scanner::ScanOptions& options){
    auto scan_result =kls::scanner::orchestratorador(root,options);

    if (auto* failure = std::get_if<kls::Failure<kls::scanner::ScanError>>(&scan_result)) {
      return kls::scanner::ScanResult{
          kls::Failure<kls::scanner::ScanError>{std::move(failure->error),},
      };
    }

    auto& success = std::get<kls::Success<kls::scanner::ScanOutput>>(scan_result);
    auto analyze_entries = analyzer::analyze_entries(std::move(success.value),options);
    return kls::scanner::ScanResult{
      kls::Success<kls::scanner::ScanOutput>{std::move(analyze_entries),}
    };
  }
}
