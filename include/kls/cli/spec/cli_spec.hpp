#pragma once 
#include "option_spec.hpp"
#include <array>
#include <string_view>
#include <algorithm>

namespace kls::cli::spec {
constexpr std::array<std::string_view, 1> quiet_conflicts = {"--verbose"};
constexpr std::array<std::string_view, 1> verbose_conflicts = {"--quiet"};
constexpr std::array<std::string_view, 1> depth_requirements = {"--recursive"};
struct AliasIndex{
  std::string_view alias;
  size_t spec_index = 0;
};

constexpr size_t NUM_OPTIONS = 20;

template<size_t N>
struct CliTables{
  std::array<OptionSpec,N> specs;
  std::array<AliasIndex,N> alias;
};

consteval auto build_cli_spec(){
  std::array<OptionSpec, NUM_OPTIONS> spec = {
    // SPECIAL
    OptionSpec{
        .name = "--help",
        .alias = "-H",
        .description = "Show help message and exit",
        .category = Category::SPECIAL,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--version",
        .alias = "-V",
        .description = "Display version information and exit",
        .category = Category::SPECIAL,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    
    // GLOBAL
    OptionSpec{
        .name = "--no-color",
        .alias = "",
        .description = "Disable ANSI color output (useful for logs/pipes)",
        .category = Category::GLOBAL,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--quiet",
        .alias = "-q",
        .description = "Suppress all non-essential output",
        .category = Category::GLOBAL,
        .value_type = ValueType::NONE,
        .conflicts = quiet_conflicts,
        .requirements = {},
    },
    OptionSpec{
        .name = "--verbose",
        .alias = "",
        .description = "Enable detailed diagnostic logging",
        .category = Category::GLOBAL,
        .value_type = ValueType::NONE,
        .conflicts = verbose_conflicts,
        .requirements = {},
    },
    
    // FILTERING
    OptionSpec{
        .name = "--all",
        .alias = "-a",
        .description = "Include hidden files and directories (dotfiles)",
        .category = Category::FILTERING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--recursive",
        .alias = "-r",
        .description = "Recursively traverse subdirectories",
        .category = Category::FILTERING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--depth",
        .alias = "-d",
        .description = "Limit recursion depth (requires --recursive)",
        .category = Category::FILTERING,
        .value_type = ValueType::INTEGER,
        .conflicts = {},
        .requirements = depth_requirements,
    },
    OptionSpec{
        .name = "--filter",
        .alias = "",
        .description = "Filter entries by glob pattern (e.g., *.conf)",
        .category = Category::FILTERING,
        .value_type = ValueType::PATTERN,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--modified-before",
        .alias = "",
        .description = "Show only files modified before given date (YYYY-MM-DD)",
        .category = Category::FILTERING,
        .value_type = ValueType::DATE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--modified-after",
        .alias = "",
        .description = "Show only files modified after given date (YYYY-MM-DD)",
        .category = Category::FILTERING,
        .value_type = ValueType::DATE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--only-findings",
        .alias = "",
        .description = "Display only entries with detected security findings",
        .category = Category::FILTERING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--min-severity",
        .alias = "",
        .description = "Filter findings by minimum severity (low|med|high|crit)",
        .category = Category::FILTERING,
        .value_type = ValueType::STRING,
        .conflicts = {},
        .requirements = {},
    },

    OptionSpec{
      .name = "--fail-on",
      .alias = "",
      .description = "Exit with code 5 if findings at or above severity exist",
      .category = Category::FILTERING,
      .value_type = ValueType::STRING,
      .conflicts = {},
      .requirements = {},
    } ,
    
    // SORTING
    OptionSpec{
        .name = "--sort",
        .alias = "",
        .description = "Sort by: name, size, type, modified, ext, findings",
        .category = Category::SORTING,
        .value_type = ValueType::STRING,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--reverse",
        .alias = "",
        .description = "Invert the sorting order",
        .category = Category::SORTING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--dirs-first",
        .alias = "",
        .description = "Group directories before files",
        .category = Category::SORTING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--findings-first",
        .alias = "",
        .description = "Prioritize entries with findings at the top",
        .category = Category::SORTING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    
    // FORMATTING
    OptionSpec{
        .name = "--long",
        .alias = "-l",
        .description = "Detailed list format (permissions, owner, size, mtime)",
        .category = Category::FORMATTING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
    OptionSpec{
        .name = "--no-header",
        .alias = "",
        .description = "Omit table headers from the output",
        .category = Category::FORMATTING,
        .value_type = ValueType::NONE,
        .conflicts = {},
        .requirements = {},
    },
  };
  
  std::ranges::sort(spec.begin(), spec.end(), [](const OptionSpec& a,const OptionSpec& b){
    return a.name < b.name;
  });

  std::array<AliasIndex,NUM_OPTIONS> alias_index;
  for(size_t i = 0 ; i < spec.size(); i++){
    AliasIndex index_alias = {
      .alias = spec[i].alias,
      .spec_index = i,
    };
    alias_index[i] = index_alias;
  }
  std::ranges::sort(alias_index.begin(), alias_index.end(), [](const AliasIndex& a, const AliasIndex& b){
    return a.alias < b.alias;
  });

  return CliTables<NUM_OPTIONS>{.specs = spec , .alias = alias_index};
}

constexpr auto COMPILATION_TABLES = build_cli_spec();
constexpr auto CLI_SPECS = COMPILATION_TABLES.specs;
constexpr auto CLI_ALIAS = COMPILATION_TABLES.alias;
}


