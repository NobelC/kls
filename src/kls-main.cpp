// src/kls-main.cpp
#include "kls/audit/audit_orchestrator.hpp"
#include "kls/cli/adapter/output_processor.hpp"
#include "kls/cli/adapter/render_option_adapter.hpp"
#include "kls/cli/adapter/scan_option_adapter.hpp"
#include "kls/cli/adapter/severity_count.hpp"
#include "kls/cli/executor/help_formatter.hpp"
#include "kls/cli/parser/cli_parser.hpp"
#include "kls/cli/validator/cli_validator.hpp"
#include "kls/detail/parse_severity.hpp"
#include "kls/report/render_report.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include "special-option/version-option.hpp"
#include <iostream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// ARCHITECTURAL NOTE: main() acts strictly as an orchestrator.
// It delegates parsing, validation, execution, and rendering to isolated domains.
// This prevents business logic from leaking into the entry point and ensures 
// the CLI contract remains stable regardless of internal scanner changes.
int main(int argc, char *argv[]) {
  // 1. Parse: Fail fast on syntax errors before touching the filesystem.
  std::vector<std::string_view> args(argv + 1, argv + argc);
  auto parse_result = kls::cli::parser::parse(args);
  if (auto *failure = std::get_if<kls::Failure<kls::cli::model::CliError>>(&parse_result)) {
    std::cerr << "kls: error: " << failure->error.message << "\n";
    std::cerr << "Run 'kls --help' for usage.\n";
    return 2; // Exit code 2: Invalid CLI arguments
  }
  auto opts = std::get<kls::Success<kls::cli::model::ParsedOptions>>(parse_result).value;

  // 2. Validate: Enforce business rules (e.g., conflicting options) independently of syntax.
  auto validate_result = kls::cli::validator::validate(opts);
  if (auto *failure = std::get_if<kls::Failure<kls::cli::model::CliError>>(&validate_result)) {
    std::cerr << "kls: error: " << failure->error.message << "\n";
    if (!failure->error.conflicting_with.empty()) {
        std::cerr << "kls: error: option '" << failure->error.option_name
                  << "' conflicts with '" << failure->error.conflicting_with << "'\n";
    }
    std::cerr << "Run 'kls --help' for usage.\n";
    return 2; // Exit code 2: Invalid CLI arguments
  }
  opts = std::get<kls::Success<kls::cli::model::ParsedOptions>>(validate_result).value;

  // 3. Special Handlers: Short-circuit execution for metadata requests.
  // No filesystem access occurs here, guaranteeing instant response and zero side effects.
  if (opts.help) {
    kls::cli::executor::print_help();
    return 0;
  }
  if (opts.version) {
    std::cout << "kls " << KLS_VERSION << "\n";
    std::cout << "Copyright (C) 2026 NobelC\n";
    std::cout << "License GPL-3.0-only\n";
    return 0;
  }

  // 4. Adapt & Execute: Translate CLI model to domain model and run the audit.
  // Adapters act as anti-corruption layers between the CLI and core domain models.
  auto scan_opts = kls::cli::adapter::to_scan_options(opts);
  auto scan_result = kls::auditor::audit_orchestrator(opts.target_path, scan_opts);
  
  // Handle fatal scan errors (e.g., root path doesn't exist). 
  // Exit code 4: Internal failure or unrecoverable target state.
  if (auto *failure = std::get_if<kls::Failure<kls::scanner::ScanError>>(&scan_result)) {
    std::cerr << "kls: error: audit failed: " << failure->error.path << "\n";
    switch (failure->error.code) {
    case kls::scanner::ScanErrorCode::root_not_found:
        std::cerr << "kls: error: path does not exist\n";
        break;
    case kls::scanner::ScanErrorCode::root_not_directory:
        std::cerr << "kls: error: path is not a directory\n";
        break;
    case kls::scanner::ScanErrorCode::root_permission_denied:
        std::cerr << "kls: error: permission denied\n";
        break;
    case kls::scanner::ScanErrorCode::root_open_failed:
        std::cerr << "kls: error: failed to open path\n";
        break;
    case kls::scanner::ScanErrorCode::unknown:
        std::cerr << "kls: error: internal failure\n";
        break;
    }
    return 4;
  }

  // 5. Process & Render: Apply user filters/sorting, then output the result.
  auto scan_output = std::get<kls::Success<kls::scanner::ScanOutput>>(scan_result).value;
  auto severity_counts = kls::cli::adapter::count_findings_by_severity(scan_output);
  
  // Mutates scan_output in-place to apply filtering/sorting. 
  // Kept separate from rendering to allow future structured outputs (JSON/CSV) to reuse the same pipeline.
  kls::cli::adapter::process_output(scan_output, opts);
  
  auto render_opts = kls::cli::adapter::to_render_options(opts);
  kls::report::render_report(std::cout, scan_output, render_opts);

  // 6. Policy Evaluation: Exit code 5 is reserved for explicit threshold breaches.
  // Findings alone do not cause failure; the user must explicitly opt-in via --fail-on.
  if (opts.fail_on.has_value()) {
    auto threshold = parser_severity(*opts.fail_on);
    if (threshold.has_value() && severity_counts.at_or_above(*threshold)) {
      return 5;
    }
  }

  // 7. Integrity Check: Exit code 3 indicates a compromised audit.
  // We do not fail on expected environmental conditions (e.g., EACCES on subdirectories),
  // only on integrity failures that invalidate the scan's trustworthiness.  
  bool has_critical_issue = false;
  for(const auto& issue : scan_output.issues){
    if(issue.code == kls::scanner::ScanIssueCode::entry_identity_changed || issue.code == kls::scanner::ScanIssueCode::invalid_discovery_reference){
      has_critical_issue = true;
      break;
    }
  }
    
  if(has_critical_issue){
    std::cerr << "kls: warning: audit completed with critical integrity issues.\n";
    return 3;
  }

  // 8. Success: Audit completed. Findings may exist, but the process ran to completion.
  return 0;
}
