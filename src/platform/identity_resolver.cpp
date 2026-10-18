#include <cerrno>
#include "kls/platform/identity_resolver.hpp"
#include <pwd.h>
#include <grp.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace kls::platform {

// ARCHITECTURAL NOTE: Caches UID/GID lookups.
// Prevents redundant, potentially slow NSS (e.g., LDAP/NIS) queries for the same ID 
// during large directory traversals.
[[nodiscard]] std::string_view IdentityResolver::owners_name(uid_t uid) {
  auto it = owners_.find(uid);
  if (it != owners_.end()) {
    return it->second;
  }

  struct passwd pwd;
  struct passwd *result_owner = nullptr;

  // Fallback to 16KB if sysconf fails or returns -1.
  long s = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t bufflen = (s == -1) ? 16384 : static_cast<size_t>(s);

  std::vector<char> buffer(bufflen);
  int s_err;
  
  // ARCHITECTURAL NOTE: Dynamic buffer expansion.
  // Some systems have deeply nested group memberships or long names. 
  // We loop on ERANGE to safely resize without truncation or undefined behavior.
  while ((s_err = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result_owner)) == ERANGE) {
    buffer.resize(buffer.size() * 2);
  }

  if (s_err != 0) {
    throw std::system_error(s_err, std::generic_category(), "getpwuid_r failed");
  }

  if (result_owner == nullptr) {
    owners_[uid] = "UNKNOWN";
    return owners_[uid];
  }

  owners_[uid] = result_owner->pw_name;
  return owners_[uid];
}

[[nodiscard]] std::string_view IdentityResolver::groups_name(gid_t gid) {
  auto it = groups_.find(gid);
  if (it != groups_.end()) {
    return it->second;
  }

  struct group gp;
  struct group *result_group = nullptr;

  long s = sysconf(_SC_GETGR_R_SIZE_MAX);
  size_t bufflen = (s == -1) ? 16384 : static_cast<size_t>(s);

  std::vector<char> buffer(bufflen);
  int s_err;
  
  while ((s_err = getgrgid_r(gid, &gp, buffer.data(), buffer.size(), &result_group)) == ERANGE) {
    buffer.resize(buffer.size() * 2);
  }

  if (s_err != 0) {
    throw std::system_error(s_err, std::generic_category(), "getgrgid_r failed");
  }

  if (result_group == nullptr) {
    groups_[gid] = "UNKNOWN";
    return groups_[gid];
  }

  groups_[gid] = result_group->gr_name;
  return groups_[gid];
}

} // namespace kls::platform
