#include "kls/cli/adapter/output_processor.hpp"
#include "kls/filesystem/file_type.hpp"
#include <algorithm>
#include <ctime>
#include <fnmatch.h>
#include <string>
#include <tuple>

namespace kls::cli::adapter {

namespace {

// ─── Helpers de fecha ────────────────────────────────────────────────────────

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


bool has_findings(const scanner::AuditItem& item) {
    if (item.health_findings.has_value() && !item.health_findings->empty()) {
        return true;
    }
    if (item.finding_capabilities.has_value() && !item.finding_capabilities->empty()) {
        return true;
    }
    return false;
}



void apply_filter(scanner::ScanOutput& output, const std::string& pattern) {
    std::erase_if(output.items, [&pattern](const scanner::AuditItem& item) {
        return fnmatch(pattern.c_str(), item.entry.name.c_str(), 0) != 0;
    });
}

void apply_modified_before(scanner::ScanOutput& output, const std::string& date_str) {
    std::time_t cutoff;
    if (!parse_date(date_str, cutoff)) {return;}
    
    std::erase_if(output.items, [cutoff](const scanner::AuditItem& item) {
        return item.entry.mtime >= cutoff;
    });
}

void apply_modified_after(scanner::ScanOutput& output, const std::string& date_str) {
    std::time_t cutoff;
    if (!parse_date(date_str, cutoff)) {return;}
    
    std::erase_if(output.items, [cutoff](const scanner::AuditItem& item) {
        return item.entry.mtime <= cutoff;
    });
}

void apply_only_findings(scanner::ScanOutput& output) {
    std::erase_if(output.items, [](const scanner::AuditItem& item) {
        return !has_findings(item);
    });
}



void apply_sort(scanner::ScanOutput& output, const std::string& criteria) {
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

void apply_dirs_first(scanner::ScanOutput& output) {
    std::ranges::stable_sort(output.items, [](const auto& a, const auto& b) {
        bool a_dir = (a.entry.type == kls::filesystem::FileType::directory);
        bool b_dir = (b.entry.type == kls::filesystem::FileType::directory);
        if (a_dir != b_dir) {return a_dir;}
        return a.entry.name < b.entry.name;
    });
}

void apply_findings_first(scanner::ScanOutput& output) {
    std::ranges::stable_sort(output.items, [](const auto& a, const auto& b) {
        bool a_has = has_findings(a);
        bool b_has = has_findings(b);
        if (a_has != b_has) {return a_has;}
        return a.entry.name < b.entry.name;
    });
}

} // namespace

void process_output(scanner::ScanOutput& output, const model::ParsedOptions& opts) {
    
    if (opts.filter.has_value()) {
        apply_filter(output, *opts.filter);
    }
    if (opts.modified_before.has_value()) {
        apply_modified_before(output, *opts.modified_before);
    }
    if (opts.modified_after.has_value()) {
        apply_modified_after(output, *opts.modified_after);
    }
    if (opts.only_findings) {
        apply_only_findings(output);
    }
  
    if (opts.sort.has_value()) {
        apply_sort(output, *opts.sort);
    }
    if (opts.dirs_first) {
        apply_dirs_first(output);
    }
    if (opts.findings_first) {
        apply_findings_first(output);
    }
    
    if (opts.reverse) {
        std::ranges::reverse(output.items);
    }
}

} // namespace kls::cli::adapter
