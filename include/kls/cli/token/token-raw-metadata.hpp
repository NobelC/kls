#pragma once
#include <cstdint>
#include <string_view>

enum class TypeToken : std::uint8_t {
  OPTION_NOT_NORMALIZED,
  OPTION_NORMALIZED,

  LITERAL,
  POSITIONAL,
};

struct Token {
  TypeToken type;
  std::string_view name;
  std::string_view value;

  bool operator==(const Token &other) const noexcept {
    return type == other.type && name == other.name;
  }
};

