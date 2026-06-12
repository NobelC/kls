#include "../../include/core-hpp/executor.hpp"
#include "../../include/token/group-token.hpp"
#include "../../src/command-register-information/command-hanlder-include.hpp"
#include "../../include/special-option/help-option.hpp"
#include "../../include/token/token-raw-metadata.hpp"
#include <algorithm>

void executor(const GroupToken& token_group){
  bool helper_call = std::ranges::any_of(token_group.options, [](const Token& t){
          return t.name == "--help" || t.name == "-h";
    });

  if(helper_call){
    HELP_HANDLER("kls");
    return;
  }
  LIST_HANDLER(token_group);
}
