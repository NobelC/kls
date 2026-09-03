#include "kls/cli/spec/cli_spec_definition.hpp"
#include "kls/scanner/scanner.hpp"
#include "kls/detail/parse_severity.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/findings/finding_flags.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/scanner/scanner.hpp"
#include <algorithm>
#include <ctime>
#include <fnmatch.h>
#include <optional>
#include <ranges>
#include <string>
#include <tuple>
#include <vector>

namespace definition_options{
  namespace {
    bool parse_date(const std::string& date_str, std::time_t& out) {
      if (date_str.size() != 10) {return false;}
    
      int year, month, day;
      if (std::sscanf(date_str.c_str(), "%d-%d-%d", &year, &month, &day) != 3) {
        return false;
      }
    
      struct std::tm tm{};
      tm.tm_year = year - 1900;
      tm.tm_mon = month - 1;
      tm.tm_mday = day;
      tm.tm_hour = 0;
      tm.tm_min = 0;
      tm.tm_sec = 0;
      tm.tm_isdst = -1;
    
      out = std::mktime(&tm);
      return out != static_cast<std::time_t>(-1);
    }


    bool has_findings(const kls::scanner::AuditItem& item) {
      return !item.findings.empty();
    }

    kls::findings::SeverityFindings  get_max_severity(const std::vector<ID>& severities){
      if(severities.empty()){
        return kls::findings::SeverityFindings::None;
      }
      auto resolve_entity = [](const ID& id){
        const auto* finding = kls::findings::get_finding(id);
        return finding ? finding->level : kls::findings::SeverityFindings::None;
      };
      
      auto level_views = severities | std::views::transform(resolve_entity);
      return std::ranges::max(level_views);
    }
  }

void apply_filter(kls::scanner::ScanOutput& output, const std::string& pattern) {
    std::erase_if(output.items, [&pattern](const kls::scanner::AuditItem& item) {
        return fnmatch(pattern.c_str(), item.entry.name.c_str(), 0) != 0;
    });
}

void apply_modified_before(kls::scanner::ScanOutput& output, const std::string& date_str) {
    std::time_t cutoff;
    if (!parse_date(date_str, cutoff)) {return;}
    
    std::erase_if(output.items, [cutoff](const kls::scanner::AuditItem& item) {
        return item.entry.mtime >= cutoff;
    });
}

void apply_modified_after(kls::scanner::ScanOutput& output, const std::string& date_str) {
    std::time_t cutoff;
    if (!parse_date(date_str, cutoff)) {return;}
    
    std::erase_if(output.items, [cutoff](const kls::scanner::AuditItem& item) {
        return item.entry.mtime <= cutoff;
    });
}

void apply_only_findings(kls::scanner::ScanOutput& output) {
    std::erase_if(output.items, [](const kls::scanner::AuditItem& item) {
        return !has_findings(item);
    });
}

void apply_sort(kls::scanner::ScanOutput& output, const std::string& criteria) {
    auto& items = output.items;
    
    if (criteria == "name") {
        std::ranges::stable_sort(items, [](const auto& a, const auto& b) {
            return a.entry.name < b.entry.name;
        });
    } else if (criteria == "size") {
        std::ranges::stable_sort(items, [](const auto& a, const auto& b) {
            return std::tie(b.entry.size, a.entry.name) < std::tie(a.entry.size, b.entry.name);
        });
    } else if (criteria == "type") {
        std::ranges::stable_sort(items, [](const auto& a, const auto& b) {
            return std::tie(a.entry.type, a.entry.name) < std::tie(b.entry.type, b.entry.name);
        });
    } else if (criteria == "modified") {
        std::ranges::stable_sort(items, [](const auto& a, const auto& b) {
            return std::tie(a.entry.mtime, a.entry.name) < std::tie(b.entry.mtime, b.entry.name);
        });
    } else if (criteria == "ext") {
        std::ranges::stable_sort(items, [](const auto& a, const auto& b) {
            return std::tie(a.entry.extension, a.entry.name) < std::tie(b.entry.extension, b.entry.name);
        });
    }

}

void apply_dirs_first(kls::scanner::ScanOutput& output) {
    std::ranges::stable_sort(output.items, [](const auto& a, const auto& b) {
        bool a_dir = (a.entry.type == kls::filesystem::FileType::directory);
        bool b_dir = (b.entry.type == kls::filesystem::FileType::directory);
        if (a_dir != b_dir) {return a_dir;}
        return a.entry.name < b.entry.name;
    });
}

void apply_findings_first(kls::scanner::ScanOutput& output) {
    std::ranges::stable_sort(output.items, [](const auto& a, const auto& b) {
        bool a_has = has_findings(a);
        bool b_has = has_findings(b);
        if (a_has != b_has) {return a_has;}
        
        return get_max_severity(a.findings) < get_max_severity(b.findings);
    });
}

void apply_min_severity(kls::scanner::ScanOutput& output,const std::string& min_severity){
  const auto min_level = parser_severity(min_severity);
  if(!min_level.has_value()){
    return;
  }

  for(auto& items : output.items){
    std::erase_if(items.findings,[min_level](const ID& id){
      const auto* findings = kls::findings::get_finding(id);
      return findings && findings->level < *min_level;
    });
  }
  std::erase_if(output.items, [](const kls::scanner::AuditItem& item){
    return item.findings.empty();
  });
}
}
