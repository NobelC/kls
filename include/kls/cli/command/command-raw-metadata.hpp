#pragma once
#include <functional>
#include <string>
#include <vector>
#include "../token/group-token.hpp"

struct CommandMetaData{
  std::string default_name;
  std::vector<std::string> option_avaible = {"--help", "--version"};
  int minimun_positional;
  int maximun_positional;
  std::function<void(const GroupToken&)> handler;
};
