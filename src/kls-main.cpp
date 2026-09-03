// src/kls-main.cpp
#include "kls/audit/audit_orchestrator.hpp"
#include "kls/cli/adapter/scan_option_adapter.hpp"
#include "kls/cli/parser/cli_parser.hpp"
#include "kls/cli/validator/cli_validator.hpp"
#include "kls/cli/executor/help_formatter.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include "special-option/version-option.hpp"
#include "kls/cli/adapter/output_processor.hpp"
#include "kls/cli/adapter/render_option_adapter.hpp"
#include "kls/report/render_report.hpp"
#include "kls/cli/adapter/severity_count.hpp"
#include "kls/detail/parse_severity.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

int main(int argc, char* argv[]) {
    // 1. Parse
    std::vector<std::string_view> args(argv + 1, argv + argc);
    auto parse_result = kls::cli::parser::parse(args);

    if (auto* failure = std::get_if<kls::Failure<kls::cli::model::CliError>>(&parse_result)) {
        std::cerr << "Error: " << failure->error.message << "\n";
        std::cerr << "Run 'kls --help' for usage.\n";
        return 2; // Invalid CLI
    }

    auto opts = std::get<kls::Success<kls::cli::model::ParsedOptions>>(parse_result).value;

    // 2. Validate
    auto validate_result = kls::cli::validator::validate(opts);
    if (auto* failure = std::get_if<kls::Failure<kls::cli::model::CliError>>(&validate_result)) {
        std::cerr << "Error: " << failure->error.message << "\n";
        if (!failure->error.conflicting_with.empty()) {
            std::cerr << "  Conflicts with: " << failure->error.conflicting_with << "\n";
        }
        std::cerr << "Run 'kls --help' for usage.\n";
        return 2; // Invalid CLI
    }

    opts = std::get<kls::Success<kls::cli::model::ParsedOptions>>(validate_result).value;

    // 3. Special Handlers
    if (opts.help) {
        kls::cli::executor::print_help();
        return 0;
    }

    if (opts.version) {
        std::cout << "kls " << KRON_VERSION << "\n";
        std::cout << "Copyright (C) 2026 NobelC\n";
        std::cout << "License MIT\n";
        return 0;
    }

    //Adapter 
    auto scan_opts = kls::cli::adapter::to_scan_options(opts);
    
    //validate target path 
    if(!std::filesystem::exists(opts.target_path)){
      std::cerr << "Error : path does not exist : " << opts.target_path << "\n";
      return 4;
    }
    if(!std::filesystem::is_directory(opts.target_path)){
      std::cerr << "Error : path is not a is_directory" << opts.target_path << "\n";
      return 4;
    }
    
    auto scan_result = kls::auditor::audit_orchestrator(opts.target_path,scan_opts);
    if(auto* failure = std::get_if<kls::Failure<kls::scanner::ScanError>>(&scan_result)){
      std::cerr << "Audit failed at:" << failure->error.path << "\n";
      switch(failure->error.code){
        case kls::scanner::ScanErrorCode::root_not_found:
          std::cerr << " Path does not exist\n";
          break;
        case kls::scanner::ScanErrorCode::root_not_directory:
          std::cerr << " Path is not a is directory\n";
          break;
        case kls::scanner::ScanErrorCode::root_permission_denied:
          std::cerr << " Permission denied\n";
          break;
        case kls::scanner::ScanErrorCode::root_open_failed:
          std::cerr << " Failed to open path\n";
          break;
        case kls::scanner::ScanErrorCode::unknown:
          std::cerr << " Error unknown, good bless\n";
      }
      return 4;
    }

    auto scan_output = std::get<kls::Success<kls::scanner::ScanOutput>>(scan_result).value;
    auto severity_counts = kls::cli::adapter::count_findings_by_severity(scan_output);
    kls::cli::adapter::process_output(scan_output, opts);
    auto render_opts = kls::cli::adapter::to_render_options(opts);
    kls::report::render_report(std::cout, scan_output, render_opts);
    if(!scan_output.issues.empty()){
      return 3;
    }
    
    if(opts.fail_on.has_value()){
      auto threshold = parser_severity(*opts.fail_on);
      if(threshold.has_value() && severity_counts.at_or_above(*threshold)){
        return 5;
      }
    }

    return 0;
}
