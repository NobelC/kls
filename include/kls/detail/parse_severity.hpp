#pragma once 
#include "kls/findings/finding_flags.hpp"
#include <optional>
#include <string_view>
#include <ranges>
#include <algorithm>

namespace {
  [[nodiscard]] constexpr char to_lower_ascii(char c) noexcept{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
  }
}

[[nodiscard]] constexpr std::optional<kls::findings::SeverityFindings> parser_severity(std::string_view severity) noexcept {
  using namespace std::string_view_literals;
  auto lowercase_view = severity | std::views::transform(to_lower_ascii);
  auto iquals = [&](std::string_view target){
    return std::ranges::equal(lowercase_view, target);
  };

  if(iquals("low"sv)){return kls::findings::SeverityFindings::Low;}
  if(iquals("medlow"sv)){return kls::findings::SeverityFindings::MedLow;}
  if(iquals("med"sv)){return kls::findings::SeverityFindings::Med;}
  if(iquals("high"sv)){return kls::findings::SeverityFindings::High;}
  if(iquals("crit"sv)){return kls::findings::SeverityFindings::Crit;}
  return std::nullopt;
}
