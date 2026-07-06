#include "../../../../kls/include/kls/cli/error/error_handler.hpp"
#include "../../../include/kls/cli/option/option-raw-metadata.hpp"
#include <iostream>
#include <string_view>
#include <format>

// cppcheck-suppress unusedFunction
[[maybe_unused]] void COMMAND_NOT_FOUND(std::string_view trigger){
  std::cerr << std::format("\n  [ERROR] Unknown command: '{}'\n", trigger);
  std::cerr << std::format("  Run 'kls --help' to see available options.\n\n");
}

void OPTION_NOT_FOUND(std::string_view trigger){
  std::cerr << std::format("\n  [ERROR] Unknown option: '{}'\n", trigger);
  std::cerr << std::format("  Run 'kls --help' to see available options.\n\n");
}

void OPTION_NEED_VALUE(std::string_view trigger, const TypeDataReceived& type_data){
  std::cerr << std::format("\n  [ERROR] Option '{}' requires a value.\n", trigger);
  std::cerr << std::format("  Expected format: ");
  switch (type_data){
    case TypeDataReceived::DATE:
      std::cerr << "YYYY-MM-DD  (e.g. 2024-01-31)\n\n";
      break;
    case TypeDataReceived::EXTENSION:
      std::cerr << ".ext        (e.g. .cpp, .docx)\n\n";
      break;
    case TypeDataReceived::SIZE:
      std::cerr << "<n><unit>   (e.g. 1024MB, 10GB)\n\n";
      break;
    case TypeDataReceived::NONE:
      std::cerr << "(none — this should not happen)\n\n";
      break;
    case TypeDataReceived::STRING:
      std::cerr << "text        (e.g. \"value\")\n\n";
      break;
  }
}

// cppcheck-suppress unusedFunction
[[maybe_unused]] void OPTION_NOT_AVAIBLE_FOR_COMMAND(std::string_view trigger, std::string_view command){
  std::cerr << std::format("\n  [ERROR] Option '{}' is not available for command '{}'.\n", trigger, command);
  std::cerr << std::format("  Run 'kls --help' to see supported options.\n\n");
}

void OPTION_CONFLICT_WITH(std::string_view trigger){
  std::cerr << std::format("\n  [ERROR] Option '{}' conflicts with another provided option.\n\n", trigger);
}

// cppcheck-suppress unusedFunction
[[maybe_unused]] void INCORRECT_NUMBER_OF_POSITIONAL_NUMBER( std::string_view command, const int& number, const int& /*min*/){
  std::cerr << std::format("\n  [ERROR] Wrong number of arguments for command '{}'.\n\n", command);
  std::cerr << std::format("  Provided : {}\n", number);
  std::cerr << std::format("  Maximum  : 1\n\n");
}

void OPTION_REQUIERES_OPTION(std::string_view option,std::string_view requieres){
  std::cerr << std::format("[ERROR] The '{}' option requires the '{}' option to work correctly",option, requieres);
}

// cppcheck-suppress unusedFunction
[[maybe_unused]] void DEFAULT_VALUE_OPTION(std::string_view option, const int& default_value){
  std::cerr << std::format("[WARNING] The '{}' option requires a value, since it does not have one in the input, its default value will be used '{}'", option, default_value);
}

// cppcheck-suppress unusedFunction
[[maybe_unused]] void EQUAL_DIRECTION(){
  std::cerr << std::format("[ERROR] The addresses entered are the same; the process will be skipped\n");
}

// cppcheck-suppress unusedFunction
[[maybe_unused]] void ORIGIN_DIRECTORY_NOT_VALITED(std::string_view dir){
  std::cerr << std::format("[ERROR] The source path is invalid\n", dir);

}
