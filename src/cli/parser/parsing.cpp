#include <kls/cli/parser/parsing.hpp>
#include <kls/cli/error/error_handler.hpp>
#include <kls/cli/option/option-implementation.hpp>
#include <kls/cli/option/option-raw-metadata.hpp>
#include <kls/cli/token/token-raw-metadata.hpp>
#include <cstddef>
#include <string>
#include <vector>

GroupToken parsing(const std::vector<Token> &token_raw) {
  GroupToken token_clasificated;

  // Handling and verification of existence
  for (size_t pos = 0; pos < token_raw.size(); pos++) {
    const auto &individual_token = token_raw[pos];

    // Check is an option exists
    if (individual_token.type == TypeToken::OPTION_NOT_NORMALIZED) {
      // Long Option
      if (individual_token.name.starts_with("--")) {
        const auto equal_pos = individual_token.name.find('=');
        // Long Option without equal sign
        if (equal_pos == std::string::npos) {
          const auto &data_token = GetOptionData(individual_token.name);
          if (data_token == nullptr) {
            OPTION_NOT_FOUND(individual_token.name);
            token_clasificated.is_valid = false;
            return token_clasificated;
          }
          // For long options without a match but that require a value
          if (data_token->data_type != TypeDataReceived::NONE) {
            if (pos + 1 < token_raw.size() &&
                token_raw[pos + 1].type == TypeToken::LITERAL) {
              const auto &next_token = token_raw[pos + 1];
              token_clasificated.options.emplace_back(Token{
                  .type = TypeToken::OPTION_NORMALIZED,
                  .name = data_token->normalized_name,
                  .value = next_token.name,
              });
              pos++;
              continue;
            } else {
              OPTION_NEED_VALUE(individual_token.name, data_token->data_type);
              token_clasificated.is_valid = false;
              return token_clasificated;
            }
          }
          token_clasificated.options.emplace_back(Token{
              .type = TypeToken::OPTION_NORMALIZED,
              .name = data_token->normalized_name,
              .value = "",
          });
          continue;
        } else {
          // For long options with equals sign
          const auto &data_token =
              GetOptionData(individual_token.name.substr(0, equal_pos));
          if (data_token == nullptr) {
            OPTION_NOT_FOUND(individual_token.name);
            token_clasificated.is_valid = false;
            return token_clasificated;
          }
          token_clasificated.options.emplace_back(Token{
              .type = TypeToken::OPTION_NORMALIZED,
              .name = data_token->normalized_name,
              .value = individual_token.name.substr(equal_pos + 1),
          });
          continue;
        }
      }
      // For short options with or without an equals sign, grouped with or without an equals sign
      for (size_t i = 0; i < individual_token.name.size(); i++) {
        if (individual_token.name[i] == '-') {
          continue;
        }
        const std::string flag = {'-', individual_token.name[i]};
        const auto &data_token = GetOptionData(flag);
        if (data_token == nullptr) {
          OPTION_NOT_FOUND(flag);
          token_clasificated.is_valid = false;
          return token_clasificated;
        }
        if (data_token->data_type != TypeDataReceived::NONE) {
          if (i + 1 < individual_token.name.size() &&
              individual_token.name[i + 1] == '=') {
            const auto &equal_pos = individual_token.name.find('=');
            if (equal_pos != std::string::npos) {
              token_clasificated.options.emplace_back(Token{
                  .type = TypeToken::OPTION_NORMALIZED,
                  .name = data_token->normalized_name,
                  .value = individual_token.name.substr(equal_pos + 1),
              });
              break;
            }
          }
          // For the special case of -o that requires a value (if 
          // grouped, it will raise an error if there is no value and it needs one)
          else if (i + 1 >= individual_token.name.size() &&
                   pos + 1 < token_raw.size() &&
                   token_raw[pos + 1].type == TypeToken::LITERAL) {
            token_clasificated.options.emplace_back(Token{
                .type = TypeToken::OPTION_NORMALIZED,
                .name = data_token->normalized_name,
                .value = token_raw[pos + 1].name,
            });
            pos++;
            break;
          } else {
            OPTION_NEED_VALUE(flag, data_token->data_type);
            token_clasificated.is_valid = false;
            return token_clasificated;
          }
        }

        token_clasificated.options.emplace_back(Token{
            .type = TypeToken::OPTION_NORMALIZED,
            .name = data_token->normalized_name,
            .value = "",
        });
      }
      continue;
    }

    token_clasificated.positional.emplace_back(Token{
        .type = TypeToken::POSITIONAL,
        .name = individual_token.name,
        .value = "",
    });
  }

  return token_clasificated;
}
