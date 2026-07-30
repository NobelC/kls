#include "../../include/kls/cli/option/option-implementation.hpp"
#include "../../include/kls/cli/option/option-raw-metadata.hpp"
#include "../../include/kls/cli/token/group-token.hpp"
#include "../../include/kls/cli/token/token-raw-metadata.hpp"

//============================= NEW IMPLEMENTATIONS
#include "../../include/kls/audit/audit_entry.hpp"
#include "../../include/kls/report/render_report.hpp"
#include "../../SUID-SGID-register/health-register.hpp"
#include "../../CAPABILITIES-register/capabilities-register.hpp"
#include "kls/audit/audit_orchestrator.hpp"
#include "kls/result.hpp"
#include "kls/scanner/scanner.hpp"
#include <algorithm>

#include <dirent.h>
#include <filesystem>
#include <format>
#include <grp.h>
#include <iostream>

#include <limits>
#include <linux/limits.h>
#include <linux/stat.h>
#include <memory>
#include <pwd.h>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctime>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <condition_variable>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <variant>

#ifndef VFS_CAP_REVISION_MASK
#define VFS_CAP_REVISION_MASK 0xff000000
#endif

namespace {
time_t TIME_NOW = time(nullptr);

}// namespace

void LIST_HANDLER(const GroupToken &token_group) {
  CreatedHealthFlags();
  CreatedCapabilityFlags();
  
  auto exist_option_without_value = [&token_group](std::string_view option)->bool{
    bool option_result = std::ranges::any_of(token_group.options, [&option](const Token& t){
      return t.name == option;
    });
    return option_result;
  };
  
  kls::scanner::ScanOptions options;
  options.analyze_capabilities = !exist_option_without_value("--capability");
  options.analyze_health = !exist_option_without_value("--health");
  options.recursive = exist_option_without_value("--recursive");
  options.include_hidden = exist_option_without_value("--all");


  std::string start_path =
      token_group.positional.empty()
          ? "."
          : std::string(token_group.positional.front().name);

  if (!std::filesystem::exists(start_path)) {
    std::cerr << std::format("ERROR: {} NO EXISTE\n", start_path);
    return;
  }

  //===============================================================================================================================
  kls::scanner::ScanResult result_audit = kls::auditor::audit_orchestrator(start_path, options);
  
  if(auto* failure = std::get_if<kls::Failure<kls::scanner::ScanError>>(&result_audit)){
    std::cerr << "kls : scan failed " << failure->error.system_error.message() << '\n';
    return;
  }
  

const auto& success = std::get<kls::Success<kls::scanner::ScanOutput>>(result_audit);
  const kls::scanner::ScanOutput& Scan_output = success.value;
  

  kls::report::RenderOptions render_options{};
  render_options.show_headers = exist_option_without_value("--no-headers");
  render_options.show_findings = options.analyze_capabilities || options.analyze_health;

  kls::report::render_report(
    std::cout,Scan_output ,render_options
    );
}
