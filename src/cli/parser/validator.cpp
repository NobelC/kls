#include <kls/cli/parser/validator.hpp>
#include <kls/cli/error/error_handler.hpp>
#include <kls/cli/option/option-implementation.hpp>
#include <kls/cli/option/option-raw-metadata.hpp>
#include <kls/cli/token/token-raw-metadata.hpp>
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iterator>
#include <ranges>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace {
bool DATE_VALIDATED(const std::string_view &date_str) {
  if (date_str.empty()) {
    return false;
  }
  std::tm tm{};
  std::istringstream str_validated{std::string(date_str)};

  str_validated >> std::get_time(&tm, "%Y-%m-%d");
  return !str_validated.fail();
}

bool SIZE_VALIDATED(std::string_view size_str) {
//The format for file sizes is varied = 1028MB or 1028GB
//For values that are numeric (1028) without specifying the
//unit, we use MB as the standard.  
  if (size_str.empty()) {
    return false;
  }

  auto digits = size_str | std::views::take_while(::isdigit);
  const auto num_digits = static_cast<size_t>(std::ranges::distance(digits));

  if (num_digits == 0) {
    return false;
  }
  if (num_digits == size_str.size()) {
    return true;
  }

  const auto unit = size_str.substr(num_digits);
  constexpr std::array valid_units = {
      // ← std::array en vez de C-style array
      std::string_view{"B"},  std::string_view{"KB"}, std::string_view{"MB"},
      std::string_view{"GB"}, std::string_view{"TB"}, std::string_view{"b"},
      std::string_view{"kb"}, std::string_view{"mb"}, std::string_view{"gb"},
      std::string_view{"tb"}};

  return std::ranges::any_of(valid_units,
                             [unit](std::string_view u) { return u == unit; });
}

bool EXTENSION_VALIDATED(std::string_view extension_str) {
  if (extension_str.empty()) {
    return false;
  }

  std::istringstream str_temp{std::string(extension_str)};
  std::string token;

  while (std::getline(str_temp, token, ',')) {
    std::string_view str(token);
    
    if (str.starts_with('.')) {
      str.remove_prefix(1);
    }

    if (str.empty()) {
      return false;
    }

    bool is_valid = std::ranges::none_of(str, [](char c) {
      return c == '/' || c == '\\' || c == ' ';
    });

    if (!is_valid) {
      return false;
    }
  }
  return true;
}
} // namespace

bool ValidationGroupToken(GroupToken &group_raw) {
  if (!group_raw.is_valid) {
    return false;
  }

  if (group_raw.positional.empty()) {
    group_raw.positional.emplace_back(Token{
        .type = TypeToken::POSITIONAL,
        .name = ".",
        .value = "",
    });
  }

  // Remove duplicate options (only the first option entered will be valid)
  std::unordered_set<std::string_view> eliminated_duplicated_option;
  eliminated_duplicated_option.reserve(group_raw.options.size());
  std::vector<Token> option_not_duplicated;
  option_not_duplicated.reserve(group_raw.options.size());

  for (const auto &option : group_raw.options) {
    if (eliminated_duplicated_option.contains(option.name)) {
      continue;
    }
    option_not_duplicated.emplace_back(option);
    eliminated_duplicated_option.insert(option.name);
  }

  group_raw.options = option_not_duplicated;
  for (const auto &element : group_raw.options) {
    const auto &option_data = GetOptionData(element.name);
    if (option_data == nullptr) {
      continue; // Should have been caught by parsing, but safety first
    }
    
    // Comprobamos si alguna opcion tiene conflictos con otra
    auto conflict_it = std::ranges::find_if(
        option_data->conflict_name, [&](const auto &conflict_option) {
          return eliminated_duplicated_option.contains(conflict_option);
        });
    if (conflict_it != option_data->conflict_name.end()) {
      OPTION_CONFLICT_WITH(*conflict_it);
      return false;
    }

    auto requires_it = std::ranges::find_if(
        option_data->requieres_name, [&](const auto &requieres_option) {
          return !eliminated_duplicated_option.contains(requieres_option);
        });
    if (requires_it != option_data->requieres_name.end()) {
      OPTION_REQUIERES_OPTION(option_data->normalized_name, *requires_it);
      return false;
    }

    // Validate expected data type:
    switch (option_data->data_type) {
    case TypeDataReceived::DATE:
      if (!DATE_VALIDATED(element.value)) {

        return false;
      }
      break;
    case TypeDataReceived::EXTENSION:
      if (!EXTENSION_VALIDATED(element.value)) {
        return false;
      };
      break;
    case TypeDataReceived::SIZE:
      if (!SIZE_VALIDATED(element.value)) {
        return false;
      }
      break;
    case TypeDataReceived::STRING:
      if (element.value.empty() || element.value == " ") {
        return false;
      }
      break;
    case TypeDataReceived::NONE:
      break;
    }
  }

  // Sort options based on their execution chronology
  std::ranges::sort(group_raw.options, [](const Token &a, const Token &b) {
    return static_cast<uint8_t>(GetOptionData(a.name)->category) <
           static_cast<uint8_t>(GetOptionData(b.name)->category);
  });

  return true;
}
