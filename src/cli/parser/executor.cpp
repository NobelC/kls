#include <kls/cli/parser/executor.hpp>
#include <kls/cli/token/group-token.hpp>
#include "../command/command-handler-include.hpp"
#include <kls/cli/special-option/help-option.hpp>
#include <kls/cli/token/token-raw-metadata.hpp>
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
