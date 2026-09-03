#pragma once 
#include "kls/scanner/scanner.hpp"
#include <fnmatch.h>
#include <string>

namespace definition_options{
  void apply_filter(kls::scanner::ScanOutput& output, const std::string& pattern);
  void apply_modified_before(kls::scanner::ScanOutput& output, const std::string& date_str);
  void apply_modified_after(kls::scanner::ScanOutput& output, const std::string& date_str);
  void apply_only_findings(kls::scanner::ScanOutput& output);
  void apply_sort(kls::scanner::ScanOutput& output, const std::string& criteria);
  void apply_dirs_first(kls::scanner::ScanOutput& output);
  void apply_findings_first(kls::scanner::ScanOutput& output);
  void apply_min_severity(kls::scanner::ScanOutput& output,const std::string& min_severity);
}
