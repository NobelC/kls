#pragma once

#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <string>

namespace kls::platform{
  class IdentityResolver{
    public:
      [[nodiscard]] std::string_view owners_name(uid_t uid);
      [[nodiscard]] std::string_view groups_name(gid_t gid);

    private:
      std::unordered_map<uid_t, std::string> owners_;
      std::unordered_map<gid_t, std::string> groups_;
  };
}
