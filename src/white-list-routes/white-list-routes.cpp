#include "white-list-routes.hpp"

#include <unordered_set>
#include <string_view>
#include "../../include/transparent-hash.hpp"

static std::unordered_set<std::string_view, transparent_hash,transparent_equal> white_list_table = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/lib",          
        "/usr/lib64",        
        "/usr/libexec"      
};

bool IsKnowPath(std::string_view path){
  for(const auto& route : white_list_table){
    if(path.starts_with(route)){
      if(path.size() == route.size() || path[route.size()] == '/'){
        return true;
      }
    }
  }
  return false;
}
