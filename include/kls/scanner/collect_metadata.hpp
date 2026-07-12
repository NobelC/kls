#pragma once
#include "scanner.hpp"

namespace kls::scanner {
  [[nodiscard]] kls::scanner::ScanOutput collect_metadata(kls::scanner::DiscoveredOutput discovered_output); 
}
