// #include "../include/command/command-implementation.hpp"
#include "../include/kls/cli/parser/executor.hpp"
#include "../include/kls/cli/parser/parsing.hpp"
#include "../include/kls/cli/parser/tokenization.hpp"
#include "../include/kls/cli/parser/validator.hpp"
#include "../include/kls/cli/option/option-implementation.hpp"
#include "../include/kls/cli/token/group-token.hpp"
#include <string>
#include <vector>

int main(int argc, char *argv[]) {
  CreatedOptionData();

  std::vector<std::string> arguments_raw(argv + 1, argv + argc);
  
  std::vector<Token> group_token_raw = tokenization(arguments_raw);
  GroupToken group_token_final = parsing(group_token_raw);
  
  if (!ValidationGroupToken(group_token_final)) {
    return 1;
  }
  executor(group_token_final);

  return 0;
}
