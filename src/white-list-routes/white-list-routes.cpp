#include "white-list-routes.hpp"

#include <algorithm>
#include <array>
#include <string_view>

constexpr std::array<std::string_view, 13> WHITELISTROUTES{
    "/bin/",  
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",          
    "/usr/lib64/",        
    "/usr/libexec/",      
    "/opt/",              
    "/snap/bin/",         
    "/snap/core/",        
    "/usr/games/"
};

[[nodiscard]] bool IsKnowPath(std::string_view path) noexcept {

  return std::ranges::any_of(WHITELISTROUTES.begin(), WHITELISTROUTES.end(), [&](std::string_view compare){
      for(const auto routes : WHITELISTROUTES){
        if(compare.starts_with(routes)){
          return true;
        }
      }
      return false;
      });
}
