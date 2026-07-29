#include "../../include/kls/scanner/scanner.hpp"
#include "kls/result.hpp"
#include "kls/scanner/collect_metadata.hpp"


#include <variant>
namespace kls::scanner{
  [[nodiscard]] kls::scanner::ScanResult orchestrator(const std::string& root, const kls::scanner::ScanOptions& options){
  DiscoveryResult discovery_result = discover_entries(root,options);
    if(auto* failure = std::get_if<kls::Failure<ScanError>>(&discovery_result)){
      return ScanResult{
        kls::Failure<ScanError>{std::move(failure->error),},
      };
    }



    auto& success = std::get<kls::Success<DiscoveredOutput>>(discovery_result);
    return ScanResult{
      kls::Success<ScanOutput>{collect_metadata(std::move(success.value))},
    };
  }
}
