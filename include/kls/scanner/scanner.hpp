#pragma once

#include "kls/audit/audit_entry.hpp"
#include <system_error>
#include <filesystem>

namespace  kls::scanner {
  struct ScanOption{
    bool recursive = false;
    bool include_hidden = false;
  };

  struct ScanError{
    std::filesystem::path path;
    std::error_code error;
  };

  [[nodiscard]] void scan() 

}
