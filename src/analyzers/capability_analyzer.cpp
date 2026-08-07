#include "kls/analyzers/capability_analyzer.hpp"
#include "kls/findings/finding_flags.hpp"
#include "../CAPABILITIES-register/capabilities-register.hpp"
#include <array>
#include <string>
#include <string_view>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <linux/capability.h>

std::vector<ID> kls::analyzer::analyze_capability(const kls::auditor::AuditEntry &fe){
    std::vector<ID> finding_entry = {};
    auto AddCapability = [&](ID id) {
        const kls::findings::Finding* flag = GetCapabilityFlag(id);
        if (flag) {
          finding_entry.emplace_back(id);
        }
  };
  std::array<uint8_t,64> buffer;
  std::memset(buffer.data(), 0, sizeof(buffer));
  ssize_t size = getxattr(std::string(fe.full_path).c_str(), XATTR_NAME_CAPS ,buffer.data(), sizeof(buffer));

  if(size <= 0){
    return finding_entry;
  }

  if(size > 0 ){
    AddCapability(ID("CA01"));
  }
  auto* cap_struct = reinterpret_cast<struct vfs_cap_data*>(buffer.data());
  uint32_t magic_etc = cap_struct->magic_etc;
  uint32_t version = magic_etc & VFS_CAP_REVISION_MASK;

  if(version != VFS_CAP_REVISION_1 && version != VFS_CAP_REVISION_2 && version != VFS_CAP_REVISION_3){
    AddCapability(ID{"CA28"});
    return finding_entry;
  }

  uint64_t permitted = ((uint64_t)cap_struct->data[1].permitted << 32) | cap_struct->data[0].permitted;
  uint64_t inheritable = ((uint64_t)cap_struct->data[1].inheritable << 32) | cap_struct->data[0].inheritable;

  if(permitted == 0 && inheritable == 0){
    AddCapability(ID{"CA35"});
  }
  if(inheritable != 0){
    AddCapability(ID{"CA36"});
  }
  if(permitted & ((1ULL << 21) | (1ULL << 19) | (1ULL << 16))){
    AddCapability(ID{"CA25"});
  }
  if(permitted & ((1ULL << 7) | (1ULL << 6) | (1ULL << 0))){
    AddCapability(ID{"CA26"});
  }
  if(permitted & ((1ULL << 13) | (1Ull <<12))){
    AddCapability(ID{"CA27"});
  }
  if(permitted & ((1ULL << 1) | (1Ull << 2))){
    AddCapability(ID{"CA30"});
  }
  if(permitted & ((1ULL << 3) | (1ULL << 4))){
    AddCapability(ID{"CA31"});
  }
  if(permitted & ((1ULL << 18))){
    AddCapability(ID{"CA32"});
  }
  if(permitted & ((1ULL << 17))){
    AddCapability(ID{"CA33"});
  }
  if(permitted & ((1ULL << 29) | (1ULL << 30))){
    AddCapability(ID{"CA34"});
  }
  return finding_entry;
}
