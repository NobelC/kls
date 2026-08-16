// include/kls/cli/model/cli_error.hpp
#pragma once
#include <string>
#include <cstdint>

namespace kls::cli::model {

enum class ErrorCode : uint8_t {
    UNKNOWN_OPTION,
    MISSING_VALUE,
    INVALID_VALUE,
    CONFLICTING_OPTIONS,
    MISSING_REQUIRED_OPTION,
    INVALID_POSITIONAL,
};

struct CliError {
    ErrorCode code = ErrorCode::UNKNOWN_OPTION;
    std::string option_name;      
    std::string conflicting_with; 
    std::string expected_value;  
    std::string actual_value;  
    std::string message;         
};

}
