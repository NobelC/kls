#pragma once 
#include "kls/scanner/scanner.hpp"

namespace kls::auditor {
  [[nodiscard]] kls::scanner::ScanResult audit_orchestrator(const std::string& root, const kls::scanner::ScanOptions& options);
}
