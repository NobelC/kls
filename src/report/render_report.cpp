#include "kls/report/render_report.hpp"
#include "kls/detail/Id.hpp"
#include "kls/detail/parse_severity.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/findings/finding_flags.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/platform/identity_resolver.hpp"
#include "kls/report/render_option.hpp"
#include "kls/scanner/scanner.hpp"
#include <array>
#include <cstdint>
#include <ctime>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

std::vector<std::pair<kls::detail::ID, std::string>>
    collection_of_alerts_for_file;

std::string_view conversion_type_file(const kls::filesystem::FileType &type) {
  switch (type) {
  case kls::filesystem::FileType::directory:
    return "DIR";
    break;
  case kls::filesystem::FileType::block_device:
    return "BLD";
    break;
  case kls::filesystem::FileType::character_device:
    return "CHD";
    break;
  case kls::filesystem::FileType::named_pipe:
    return "NAP";
    break;
  case kls::filesystem::FileType::regular:
    return "REG";
    break;
  case kls::filesystem::FileType::symlink:
    return "SYM";
    break;
  case kls::filesystem::FileType::unix_domain_socket:
    return "UDS";
    break;
  case kls::filesystem::FileType::unknown:
    return "UNK";
    break;
  }
  return "UNK";
}
/* no es utilizada
std::string format_size(const std::uint64_t &size) {
  auto size_final = static_cast<double>(size);
  std::string size_str;
  if ((size < 1024)) {
    size_str = std::format("{:.2f} B", size_final);
  } else if (size < 1048576) {
    size_final /= 1024.0;
    size_str = std::format("{:.2f} KB", size_final);
  } else if (size < 1073741824) {
    size_final /= 1048576.0;
    size_str = std::format("{:.2f} MB", size_final);
  } else if (size < 1099511627776) {
    size_final /= 1073741824.0;
    size_str = std::format("{:.2f} GB", size_final);
  } else {
    size_final /= 1099511627776.0;
    size_str = std::format("{:.2f} TB", size_final);
  }
  return size_str;
}
*/

std::string formated_perms(const mode_t &mode) {
  std::string perms_format;
  perms_format.reserve(9);
  perms_format += (mode & S_IRUSR) ? "r" : "-";
  perms_format += (mode & S_IWUSR) ? "w" : "-";
  perms_format += (mode & S_IXUSR) ? "x" : "-";

  perms_format += (mode & S_IRGRP) ? "r" : "-";
  perms_format += (mode & S_IWGRP) ? "w" : "-";
  perms_format += (mode & S_IXGRP) ? "x" : "-";

  perms_format += (mode & S_IROTH) ? "r" : "-";
  perms_format += (mode & S_IWOTH) ? "w" : "-";
  perms_format += (mode & S_IXOTH) ? "x" : "-";

  return perms_format;
}

std::string_view
parser_severity_finding(const kls::findings::SeverityFindings &severity) {
  switch (severity) {
  case kls::findings::SeverityFindings::None:
    return "NONE";
    break;
  case kls::findings::SeverityFindings::Low:
    return "LOW";
    break;
  case kls::findings::SeverityFindings::MedLow:
    return "MEDLOW";
    break;
  case kls::findings::SeverityFindings::Med:
    return "MED";
    break;
  case kls::findings::SeverityFindings::High:
    return "HIGH";
    break;
  case kls::findings::SeverityFindings::Crit:
    return "CRIT";
    break;
  }
}

namespace kls::report {

void render_report(std::ostream &output,
                   const kls::scanner::ScanOutput &entries,
                   const kls::report::RenderOptions &option_render) {

  kls::platform::IdentityResolver Identity;
  const auto maximum_name_width = option_render.maximum_name_width;
  if (entries.items.empty()) {
    return;
  }
  if (option_render.show_headers) {
    output << std::format(
        "{:<5} {:<10} {:<8} {:<8} {:<12} {:<30} {:<10} {:<20}\n", "TYPE",
        "PERMS", "OWNER", "GROUP", "MODIFIED", "NAME", "SEVERITY", "FINDING");
  }
  output << std::string(120, '-') << "\n";

  for (size_t i = 0; i < entries.items.size(); i++) {
    auto &actual_entry = entries.items[i].entry;
    auto &actual_fiding = entries.items[i].findings;
    // 1. Perms (Mode)
    std::string perms = formated_perms(actual_entry.mode);

    // 3. Time
    std::array<char, std::size("yyyy-mm-dd")> str_time{};
    struct tm time_buffer;

    if (gmtime_r(&actual_entry.mtime, &time_buffer) != nullptr) {
      std::strftime(str_time.data(), str_time.size(), "%F", &time_buffer);
    }

    std::string type;
    type.reserve(3);
    type = conversion_type_file(actual_entry.type);

    std::string display_name = actual_entry.name;

    std::string formatted_name;
    formatted_name.reserve(display_name.size());
    formatted_name.append(display_name);

    output << std::format(
        "{:<5} {:<10} {:<8} {:<8} {:<12} {:<30} {:<10} \n", type, perms,
        Identity.owners_name(actual_entry.uid),
        Identity.groups_name(actual_entry.gid),
        std::string_view(str_time.data(), str_time.size()), formatted_name,
        parser_severity_finding(
            kls::findings::get_max_level_severity(entries.items[i].findings)));
    formatted_name.clear();
    display_name.clear();
  }
}
} // namespace kls::report
