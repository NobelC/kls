#include <kls/cli/parser/tokenization.hpp>
#include <kls/cli/token/token-raw-metadata.hpp>
#include <string>
#include <vector>
std::vector<Token> tokenization(const std::vector<std::string> &arguments) {
  std::vector<Token> argument_raw;
  argument_raw.reserve(arguments.size());
  bool only_positional = false;

  for (const auto& arg : arguments) {

    if (arg.empty() || arg == " ") {
      continue;
    }

    // Detect the delimiter "--" that forces all subsequent arguments to be
    // treated as positional
    if (arg == "--") {
      only_positional = true;
      continue;
    }

    if (arg == "-") {
      argument_raw.emplace_back(Token{
          .type = TypeToken::POSITIONAL,
          .name = arg,
          .value = "",
      });
      continue;
    }

    // Handle cases where only positional arguments are allowed (after "--")
    if (only_positional) {
      argument_raw.emplace_back(Token{
          .type = TypeToken::POSITIONAL,
          .name = arg,
          .value = "",
      });
      continue;
    }

    // Identify and store options (starting with '-') that are not yet
    // normalized
    if (arg.starts_with("-")) {
      argument_raw.emplace_back(Token{
          .type = TypeToken::OPTION_NOT_NORMALIZED,
          .name = arg,
          .value = "",
      });
      continue;
    }

    // Store remaining arguments as literal tokens
    argument_raw.emplace_back(Token{
        .type = TypeToken::LITERAL,
        .name = arg,
        .value = "",
    });
  }

  return argument_raw;
}
