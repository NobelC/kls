#include "../../../include/special-option/help-option.hpp"
#include <string>
#include <format>
#include <iostream>
#include <string_view>

// ─── Column widths ────────────────────────────────────────────────────────────
static constexpr int W_OPT   = 28;
static constexpr int W_ALIAS =  8;
static constexpr int W_TYPE  = 12;
static constexpr int W_DESC  = 50;

namespace {

/*
void print_header(std::string_view title) {
    std::cout << std::format("\n\033[1;37m{}\033[0m\n", title);
    std::cout << std::format("{}\n", std::string(title.size(), '='));
}
*/

void print_section(std::string_view title) {
    std::cout << std::format("\n\033[1;34m{}\033[0m\n", title);
}

void print_row(std::string_view opt, std::string_view alias,
               std::string_view type, std::string_view desc) {
    std::cout << std::format("  \033[1;32m{:<{}}\033[0m {:<{}} {:<{}} {}\n",
        opt,   W_OPT,
        alias, W_ALIAS,
        type,  W_TYPE,
        desc);
}

void print_table_header() {
    std::cout << std::format("  \033[1;30m{:<{}} {:<{}} {:<{}} {}\033[0m\n",
        "Option", W_OPT,
        "Alias",  W_ALIAS,
        "Type",   W_TYPE,
        "Description");
    std::cout << std::format("  {}\n", std::string(W_OPT + W_ALIAS + W_TYPE + W_DESC + 3, '-'));
}

void help_kls() {
    std::cout << "\033[1;36mkls [path] [options]\033[0m\n";
    std::cout << "The Security-Focused Directory Auditor\n";

    print_section("SYNOPSIS");
    std::cout << "  kls is a specialized directory listing tool designed for security auditing,\n"
              << "  attack surface analysis, and system health checks. It provides deep visibility\n"
              << "  into file metadata, permission anomalies, and potential security risks.\n";

    print_section("ARGUMENTS");
    std::cout << std::format("  {:<20} {}\n", "[path]", "Target directory for analysis. Defaults to '.' (current directory).");

    print_section("GLOBAL OPTIONS");
    print_table_header();
    print_row("--help",            "-h", "NONE",   "Show this comprehensive help message and exit.");
    print_row("--version",         "-v", "NONE",   "Display version information and build metadata.");
    print_row("--no-color",        "—",  "NONE",   "Disable ANSI color output (useful for logs/pipes).");
    print_row("--quiet",           "-q", "NONE",   "Suppress all non-essential output.");
    print_row("--verbose",         "—",  "NONE",   "Enable detailed diagnostic logging.");

    print_section("COLLECTION & FILTERING");
    print_table_header();
    print_row("--all",             "-a", "NONE",   "Include hidden files and directories (dotfiles).");
    print_row("--recursive",       "-r", "NONE",   "Recursively traverse subdirectories.");
    print_row("--depth",           "-d", "INT",    "Limit recursion depth (requires --recursive).");
    print_row("--filter",          "—",  "PATTERN","Filter entries by glob pattern (e.g., *.conf).");
    print_row("--modified-before", "—",  "DATE",   "Show only files modified before given date.");
    print_row("--modified-after",  "—",  "DATE",   "Show only files modified after given date.");
    print_row("--only-alerts",     "—",  "NONE",   "Display only items with detected security issues.");
    print_row("--only-anomalies",  "—",  "NONE",   "Filter for unusual file types or permission sets.");
    print_row("--min-severity",    "—",  "LEVEL",  "Filter alerts by minimum severity (low|med|high|crit).");

    print_section("SORTING & ORDERING");
    print_table_header();
    print_row("--sort",            "—",  "CRITERIA","Sort by: name, size, type, modified, ext, severity.");
    print_row("--reverse",         "—",  "NONE",   "Invert the sorting order.");
    print_row("--dirs-first",      "—",  "NONE",   "Group directories before files.");
    print_row("--alerts-first",    "—",  "NONE",   "Prioritize security alerts at the top of the list.");

    print_section("PRESENTATION & FORMATTING");
    print_table_header();
    print_row("--long",            "-l", "NONE",   "Detailed list format (permissions, owner, size, mtime).");
    print_row("--no-header",       "—",  "NONE",   "Omit table headers from the output.");
    print_row("--stats",           "—",  "NONE",   "Show summary statistics at the end of execution.");
    print_row("--timeline",        "—",  "NONE",   "Render results in a chronological activity view.");
    print_row("--immutable",       "—",  "NONE",   "Highlight files with immutable attributes.");

    print_section("SECURITY & AUDIT ENGINE");
    print_table_header();
    print_row("--health",          "—",  "NONE",   "Enable security health analysis (default).");
    print_row("--no-health",       "—",  "NONE",   "Disable security analysis for faster execution.");
    print_row("--attack-surface",  "—",  "NONE",   "Generate an attack surface summary for the target.");
    print_row("--security-report", "—",  "NONE",   "Output a consolidated security audit report.");
    print_row("--setuid-tree",     "—",  "NONE",   "Specifically audit for SETUID/SETGID binaries.");

    print_section("OPTION CONFLICTS & RULES");
    std::cout << "  • --quiet and --verbose are mutually exclusive.\n"
              << "  • --health is enabled by default; --no-health explicitly overrides it.\n"
              << "  • --depth requires --recursive to be effective.\n"
              << "  • --all is the default behavior when auditing; use --no-hidden to override (if planned).\n"
              << "  • Security sorting (--sort=severity) is implied when --alerts-first is used.\n";

    std::cout << "\n\033[1;30mNote: Some advanced audit options are currently in experimental phase.\033[0m\n";
}

} // namespace

void HELP_HANDLER(std::string_view /*option_help*/) {
    help_kls();
}
