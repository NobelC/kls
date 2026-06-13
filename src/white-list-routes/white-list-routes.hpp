#pragma once
#include <string_view>

void CreatedWhiteList();
[[nodiscard]] bool IsKnowPath(std::string_view path) noexcept;
