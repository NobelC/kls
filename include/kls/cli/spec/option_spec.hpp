#pragma once 
#include <cstdint>
#include <span>
#include <string_view>

namespace kls::cli::spec { 
  enum class Category : uint8_t{
    GLOBAL,
    FILTERING,
    SORTING,
    FORMATTING,
    SPECIAL,
  };
  
  enum class ValueType : uint8_t{
    NONE,
    STRING,
    INTEGER,
    DATE,
    SIZE,
    PATTERN,
  };
  
  struct OptionSpec{
    std::string_view name;
    std::string_view alias;
    std::string_view description;
    Category category;
    ValueType value_type;
    std::span<const std::string_view> conflicts;
    std::span<const std::string_view> requirements;
  };
}
