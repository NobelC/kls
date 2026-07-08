#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdint>

namespace kls::report{
  enum class ColorMode : uint_fast8_t{
    automatic,
    always,
    never,
  };

  enum class IdentityDisplay :uint_fast8_t{
    hidden,
    numeric,
    name,
    name_and_numeric
  };

  enum class PathDisplay :  uint_fast8_t{
    filename,
    relative,
    absolute
  };

  enum class DateDisplay :  uint_fast8_t{
    hidden,
    utc_date,
    local_date,
  };

struct RenderOptions {
    ColorMode color{ColorMode::automatic};

    IdentityDisplay owner{IdentityDisplay::name};
    IdentityDisplay group{IdentityDisplay::name};

    PathDisplay path{PathDisplay::relative};
    DateDisplay date{DateDisplay::utc_date};

    bool human_readable_size{true};
    bool show_permissions{true};
    bool show_findings{true};
    bool show_headers{true};
    bool resolve_identities{true};

    std::size_t maximum_name_width = 80;
};
}
