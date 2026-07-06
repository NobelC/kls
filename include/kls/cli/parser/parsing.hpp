#pragma once
#include "../token/group-token.hpp"
#include "../token/token-raw-metadata.hpp"
#include <vector>

GroupToken parsing(const std::vector<Token>& token_raw);
