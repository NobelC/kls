#include <cerrno>
#include "kls/platform/identity_resolver.hpp"
#include <pwd.h>
#include <grp.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace kls::platform{
  [[nodiscard]] std::string_view IdentityResolver::owners_name(uid_t uid){
    auto it = owners_.find(uid);
    if(it != owners_.end()){
      return it->second;
    }

    struct passwd pwd;
    struct passwd *result_owner = nullptr;

    long s = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t bufflen = (s == -1) ? 16384 : static_cast<size_t>(s);

    std::vector<char> buffer(bufflen);
    int s_err;
    while((s_err = getpwuid_r(uid,&pwd,buffer.data(), buffer.size(),&result_owner)) == ERANGE){
      buffer.resize(buffer.size() * 2);
    }

    if(s_err != 0){
      throw std::system_error(s_err, std::generic_category(), "fail in getpwuid_r");
    }
    
    if(result_owner == nullptr){
      owners_[uid] = "UNKNOWN";
      return owners_[uid];
    }

    if(result_owner){
      owners_[uid] = result_owner->pw_name;
      return owners_[uid];
    }

    owners_[uid] = "UNKNOWN";
    return owners_[uid];

  };

  [[nodiscard]] std::string_view IdentityResolver::groups_name(gid_t gid){
    auto it = groups_.find(gid);
    if(it != groups_.end()){
      return it->second;
    }
        


    struct group gp;
    struct group* result_group = nullptr;
    
    long s = sysconf(_SC_GETGR_R_SIZE_MAX);
    size_t bufflen = (s == -1) ? 16384 : static_cast<size_t>(s);
    std::vector<char> buffer(bufflen);

    int s_err;
    while((s_err = getgrgid_r(gid,&gp,buffer.data(),buffer.size(),&result_group)) == ERANGE ){
      buffer.resize(buffer.size() * 2);
    }

    if (s_err != 0) {
        throw std::system_error(s_err, std::generic_category(), "fail in  getgrgid_r");
    }

    if (result_group == nullptr) {
        groups_[gid] = "UNKNOWN";
        return groups_[gid];
    }

    if(result_group){
      groups_[gid] = result_group->gr_name;
      return groups_[gid];
    }
    groups_[gid] = "UNKNOWN";
    return groups_[gid];

  };
}
