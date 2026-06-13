#include "white-list-routes.hpp"

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
  for(const auto& route : WHITELISTROUTES){
    if(path.starts_with(route)){
      return true;
    }
  }
  return false;
}
