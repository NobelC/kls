#pragma once
#include <array>
#include <string_view>
#include <algorithm>

namespace kls::findings {

// Standard system paths where SUID/SGID binaries are expected and safe.
// Entries MUST be sorted for potential future binary-search optimization.
constexpr std::array<std::string_view, 13> WHITELIST_ROUTES = {{
    "/bin/",
    "/opt/",
    "/sbin/",
    "/snap/bin/",
    "/snap/core/",
    "/usr/bin/",
    "/usr/games/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/sbin/",
}};

[[nodiscard]] constexpr bool is_known_path(std::string_view path) noexcept {
    return std::ranges::any_of(WHITELIST_ROUTES, [path](std::string_view prefix) {
        return path.starts_with(prefix);
    });
}

} // namespace kls::findings
