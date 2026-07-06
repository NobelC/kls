#pragma once
#include "token-raw-metadata.hpp"
#include <vector>

struct GroupToken{
  std::vector<Token> options;
  std::vector<Token> positional;
  bool is_valid = true;

  [[nodiscard]] bool empty() const{
    return options.empty() && positional.empty();
  }
};
