// include/kls/cli/model/parsed_options.hpp
#pragma once
#include <optional>
#include <string>
#include <cstdint>

namespace kls::cli::model {

struct ParsedOptions {
    // Special
    bool help = false;
    bool version = false;
    
    // Global
    bool no_color = false;
    bool quiet = false;
    bool verbose = false;
    
    // Filtering
    bool all = false;
    bool recursive = false;
    std::optional<int32_t> depth;
    std::optional<std::string> filter;
    std::optional<std::string> modified_before;
    std::optional<std::string> modified_after;
    bool only_findings = false;
    std::optional<std::string> min_severity;
    
    // Sorting
    std::optional<std::string> sort;
    bool reverse = false;
    bool dirs_first = false;
    bool findings_first = false;
    
    // Formatting
    bool long_format = false;
    bool no_header = false;
    
    // Positional
    std::string target_path = ".";
};

} // namespace kls::cli::model
