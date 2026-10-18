#include "kls/cli/executor/help_formatter.hpp"
#include "kls/cli/spec/cli_spec.hpp"
#include "kls/cli/spec/option_spec.hpp"
#include <format>
#include <ostream>
#include <string>
#include <string_view>
#include <map>
#include <vector>
#include <unistd.h>

namespace kls::cli::executor {
namespace {

// Check TTY. Prevents ANSI escape codes from corrupting piped or file output.
bool use_colors() noexcept {
    return isatty(STDOUT_FILENO) != 0;
}

// Fixed widths keep terminal output aligned and readable across environments.
constexpr int W_OPT = 28;
constexpr int W_ALIAS = 8;
constexpr int W_TYPE = 12;

// Maps internal enums to user-facing strings. Decouples data model from presentation.
std::string_view category_title(spec::Category cat){
   switch (cat) {
     case spec::Category::SPECIAL:    return "SPECIAL OPTIONS";
     case spec::Category::GLOBAL:     return "GLOBAL OPTIONS";
     case spec::Category::FILTERING:  return "COLLECTION & FILTERING";
     case spec::Category::SORTING:    return "SORTING & ORDERING";
     case spec::Category::FORMATTING: return "PRESENTATION & FORMATTING";
   }
   return "OTHER";
 }

std::string_view value_type_str(spec::ValueType vt) {
   switch (vt) {
     case spec::ValueType::NONE:    return "NONE";
     case spec::ValueType::STRING:  return "STRING";
     case spec::ValueType::INTEGER: return "INT";
     case spec::ValueType::DATE:    return "DATE";
     case spec::ValueType::SIZE:    return "SIZE";
     case spec::ValueType::PATTERN: return "PATTERN";
   }
   return "UNKNOWN";
 }

// Encapsulates color branching. Keeps the main rendering loop clean.
void print_table_header(std::ostream& out, bool colors) {
   if (colors) {
       out << std::format("  \033[1;30m{:<{}} {:<{}} {:<{}} Description\033[0m\n",
                          "Option", W_OPT, "Alias", W_ALIAS, "Type", W_TYPE);
   } else {
       out << std::format("  {:<{}} {:<{}} {:<{}} Description\n",
                          "Option", W_OPT, "Alias", W_ALIAS, "Type", W_TYPE);
   }
   out << std::format("  {}\n", std::string(W_OPT + W_ALIAS + W_TYPE + 50, '-'));
 }

// Uses std::string only for the "—" fallback to satisfy std::format, 
// keeping the rest of the logic zero-allocation via string_view.
void print_row(std::ostream& out, std::string_view opt, std::string_view alias,
               std::string_view type, std::string_view desc, bool colors) {
   std::string alias_str = alias.empty() ? "—" : std::string(alias);
   
   if (colors) {
       out << std::format("  \033[1;32m{:<{}}\033[0m {:<{}} {:<{}} {}\n",
                          opt, W_OPT, alias_str, W_ALIAS, type, W_TYPE, desc);
   } else {
       out << std::format("  {:<{}} {:<{}} {:<{}} {}\n",
                          opt, W_OPT, alias_str, W_ALIAS, type, W_TYPE, desc);
   }
 }

} // namespace

// Single source of truth. Iterates `CLI_SPECS` directly. 
// If an option exists in the parser, it's here. Prevents documentation drift.
void print_help(std::ostream& out){
    const bool colors = use_colors();

    if (colors) {
        out << "\033[1;36mkls [path] [options]\033[0m\n";
    } else {
        out << "kls [path] [options]\n";
    }
    
    out << "The Security-Focused Directory Auditor\n\n";

    if (colors) {
        out << "\033[1;34mSYNOPSIS\033[0m\n";
    } else {
        out << "SYNOPSIS\n";
    }
    
    out << "  kls audits a target directory and produces findings, coverage,\n";
    out << "  diagnostics, and a deterministic exit status.\n\n";

    if (colors) {
        out << "\033[1;34mARGUMENTS\033[0m\n";
    } else {
        out << "ARGUMENTS\n";
    }
    
    out << std::format("  {:<20} {}\n\n", "[path]", "Target directory. Defaults to '.'");

    // Grouping by category reduces cognitive load. Task-oriented, not alphabetical dump.
    std::map<spec::Category, std::vector<const spec::OptionSpec*>> grouped;
    for (const auto& spec : spec::CLI_SPECS) {
        grouped[spec.category].push_back(&spec);
    }

    // Enforces strict display order. Critical options (SPECIAL, GLOBAL) always show first, 
    // regardless of underlying enum values or map iteration order.
    std::vector<spec::Category> order = {
        spec::Category::SPECIAL,
        spec::Category::GLOBAL,
        spec::Category::FILTERING,
        spec::Category::SORTING,
        spec::Category::FORMATTING
    };

    for (auto cat : order) {
        if (!grouped.contains(cat)) {continue;}
        
        if (colors) {
            out << std::format("\033[1;34m{}\033[0m\n", category_title(cat));
        } else {
            out << std::format("{}\n", category_title(cat));
        }
        
        print_table_header(out, colors);
        
        for (const auto* spec : grouped[cat]) {
            print_row(out, spec->name, spec->alias, value_type_str(spec->value_type), spec->description, colors);
        }
        out << "\n";
    }

    // Explicit exit codes are mandatory for scriptability and CI/CD automation.
    if (colors) {
        out << "\033[1;34mEXIT STATUS\033[0m\n";
    } else {
        out << "EXIT STATUS\n";
    }
    
    out << "  0  Audit completed successfully (or --help/--version)\n";
    out << "  2  Invalid CLI arguments\n";
    out << "  3  Incomplete audit (e.g., permission denied, vanished entries)\n";
    out << "  4  Internal failure\n";
    out << "  5  Configured threshold exceeded\n\n";
}
} // namespace kls::cli::executor
