#include "kls/cli/spec/cli_spec_definition.hpp"
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
#include <system_error>
#include <tuple>
#include <vector>
#include <charconv>

namespace definition_options {
namespace {

// ARCHITECTURAL NOTE: Locale-independent parsing.
// std::from_chars avoids the overhead and locale-dependency of strptime or regex.
// We strictly enforce YYYY-MM-DD to prevent ambiguous date interpretations.
bool parse_date(const std::string &date_str, std::time_t &out) {
  const char* first = date_str.data();
  const char* last = date_str.data() + date_str.size();
  
  int year = 0, month = 0, day = 0;

  auto [ptr1, ec1] = std::from_chars(first, last, year);
  if (ec1 != std::errc{} || ptr1 == last || *ptr1 != '-') {
    return false;
  }
  
  auto [ptr2, ec2] = std::from_chars(ptr1 + 1, last, month);
  if (ec2 != std::errc{} || ptr2 == last || *ptr2 != '-') {
    return false;
  }
  
  auto [ptr3, ec3] = std::from_chars(ptr2 + 1, last, day);
  if (ec3 != std::errc{} || ptr3 == last || *ptr3 != '-') {
    return false;
  }

  std::tm tm = {};
  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  tm.tm_isdst = -1;

  std::time_t time = std::mktime(&tm);
  if (time == static_cast<std::time_t>(-1)) {
    return false;
  }
  
  out = time;
  return true;
}

bool has_findings(const kls::scanner::AuditItem &item) {
  return !item.findings.empty();
}

// Maps IDs to severity levels safely.
// Returns None for unknown IDs to prevent null pointer dereferences.
kls::findings::SeverityFindings get_max_severity(const std::vector<kls::detail::ID> &severities) {
  if (severities.empty()) {
    return kls::findings::SeverityFindings::None;
  }
  
  auto resolve_entity = [](const kls::detail::ID &id) {
    const auto *finding = kls::findings::get_finding(id);
    if (finding) {
      return finding->level;
    }
    return kls::findings::SeverityFindings::None;
  };

  auto level_views = severities | std::views::transform(resolve_entity);
  return std::ranges::max(level_views);
}

} // namespace

// Uses POSIX fnmatch for globbing.
// Note: fnmatch is acceptable here as output processing is currently single-threaded.
void apply_filter(kls::scanner::ScanOutput &output, const std::string &pattern) {
  std::erase_if(output.items, [&pattern](const kls::scanner::AuditItem &item) {
    return fnmatch(pattern.c_str(), item.entry.name.c_str(), 0) != 0;
  });
}

// Silently ignores invalid dates as a defensive fallback.
// The CLI validator should ideally catch malformed dates before reaching the processor.
void apply_modified_before(kls::scanner::ScanOutput &output, const std::string &date_str) {
  std::time_t cutoff;
  if (!parse_date(date_str, cutoff)) {
    return;
  }

  std::erase_if(output.items, [cutoff](const kls::scanner::AuditItem &item) {
    return item.entry.mtime >= cutoff;
  });
}

void apply_modified_after(kls::scanner::ScanOutput &output, const std::string &date_str) {
  std::time_t cutoff;
  if (!parse_date(date_str, cutoff)) {
    return;
  }

  std::erase_if(output.items, [cutoff](const kls::scanner::AuditItem &item) {
    return item.entry.mtime <= cutoff;
  });
}

void apply_only_findings(kls::scanner::ScanOutput &output) {
  std::erase_if(output.items, [](const kls::scanner::AuditItem &item) {
    return !has_findings(item);
  });
}

// ARCHITECTURAL NOTE: Stable sort preserves original discovery order for ties.
// This ensures deterministic output across multiple runs, which is critical for CI/CD diffing.
// std::tie provides lexicographical comparison for secondary sorting (e.g., by name).
void apply_sort(kls::scanner::ScanOutput &output, const std::string &criteria) {
  auto &items = output.items;

  if (criteria == "name") {
    std::ranges::stable_sort(items, [](const auto &a, const auto &b) {
      return a.entry.name < b.entry.name;
    });
  } else if (criteria == "size") {
    std::ranges::stable_sort(items, [](const auto &a, const auto &b) {
      return std::tie(b.entry.size, a.entry.name) < std::tie(a.entry.size, b.entry.name);
    });
  } else if (criteria == "type") {
    std::ranges::stable_sort(items, [](const auto &a, const auto &b) {
      return std::tie(a.entry.type, a.entry.name) < std::tie(b.entry.type, b.entry.name);
    });
  } else if (criteria == "modified") {
    std::ranges::stable_sort(items, [](const auto &a, const auto &b) {
      return std::tie(a.entry.mtime, a.entry.name) < std::tie(b.entry.mtime, b.entry.name);
    });
  } else if (criteria == "ext") {
    std::ranges::stable_sort(items, [](const auto &a, const auto &b) {
      return std::tie(a.entry.extension, a.entry.name) < std::tie(b.entry.extension, b.entry.name);
    });
  }
}

// Primary sort: directories first. Secondary sort: alphabetical by name.
void apply_dirs_first(kls::scanner::ScanOutput &output) {
  std::ranges::stable_sort(output.items, [](const auto &a, const auto &b) {
    bool a_dir = (a.entry.type == kls::filesystem::FileType::directory);
    bool b_dir = (b.entry.type == kls::filesystem::FileType::directory);
    
    if (a_dir != b_dir) {
      return a_dir;
    }
    return a.entry.name < b.entry.name;
  });
}

// Primary sort: entries with findings. Secondary sort: highest severity first.
void apply_findings_first(kls::scanner::ScanOutput &output) {
  std::ranges::stable_sort(output.items, [](const auto &a, const auto &b) {
    bool a_has = has_findings(a);
    bool b_has = has_findings(b);
    
    if (a_has != b_has) {
      return a_has;
    }
    return get_max_severity(a.findings) > get_max_severity(b.findings);
  });
}

// Two-pass filtering:
// 1. Remove individual findings below the threshold.
// 2. Remove entries that no longer have any findings after pass 1.
void apply_min_severity(kls::scanner::ScanOutput &output, const std::string &min_severity) {
  const auto min_level = parser_severity(min_severity);
  if (!min_level.has_value()) {
    return;
  }

  for (auto &item : output.items) { // FIXED: was incorrectly named 'items'
    std::erase_if(item.findings, [min_level](const kls::detail::ID &id) {
      const auto *finding = kls::findings::get_finding(id);
      if (finding && finding->level < *min_level) {
        return true;
      }
      return false;
    });
  }
  
  std::erase_if(output.items, [](const kls::scanner::AuditItem &item) {
    return item.findings.empty();
  });
}

} // namespace definition_options
