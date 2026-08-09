// src/kls-main.cpp
#include "kls/cli/parser/cli_parser.hpp"
#include "kls/cli/validator/cli_validator.hpp"
#include "kls/cli/executor/help_formatter.hpp"
#include "special-option/version-option.hpp" // Generado por CMake (KRON_VERSION)

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

    std::cout << "Audit target: " << opts.target_path << "\n";
    if (opts.recursive) {std::cout << "  Recursive: yes\n";}
    if (opts.depth)     {std::cout << "  Max depth: " << *opts.depth << "\n";}
    if (opts.all)       {std::cout << "  Include hidden: yes\n";}

    return 0;
}
