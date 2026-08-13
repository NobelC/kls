#pragma once
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

struct transparent_hash {
  using is_transparent = void;
  std::size_t operator()(std::string_view strsv) const {
    return std::hash<std::string_view>{}(strsv);
  }
  std::size_t operator()(const std::string &str) const {
    return std::hash<std::string_view>{}(str);
  }
  std::size_t operator()(const char *chr) const {
    return std::hash<std::string_view>{}(chr);
  }
};

struct transparent_equal{
  using is_transparent = void;
  bool operator()(std::string_view opt , std::string_view its) const {
    return opt == its;
  }
};
