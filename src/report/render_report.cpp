#include "kls/report/render_report.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/findings/finding_flags.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/platform/identity_resolver.hpp"
#include "kls/report/render_option.hpp"
#include "kls/scanner/scanner.hpp"
#include <array>
#include <ctime>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

// ARCHITECTURAL FIX: Removed global `collection_of_alerts_for_file`.
// Mutable global state violates thread safety, reentrancy, and the 
// "no mutable global registries" rule. Alert collection must be 
// handled locally within the audit model or renderer context.

// Maps internal enum to fixed-width string for aligned terminal output.
std::string_view format_file_type(const kls::filesystem::FileType &type) {
  switch (type) {
  case kls::filesystem::FileType::directory:
    return "DIR";
  case kls::filesystem::FileType::block_device:
    return "BLD";
  case kls::filesystem::FileType::character_device:
    return "CHD";
  case kls::filesystem::FileType::named_pipe:
    return "NAP";
  case kls::filesystem::FileType::regular:
    return "REG";
  case kls::filesystem::FileType::symlink:
    return "SYM";
  case kls::filesystem::FileType::unix_domain_socket:
    return "UDS";
  case kls::filesystem::FileType::unknown:
    return "UNK";
  }
  return "UNK";
}

// Unused: Reserved for future human-readable size formatting.
/*
std::string format_size(const std::uint64_t &size) {
  auto size_final = static_cast<double>(size);
  std::string size_str;
  if (size < 1024) {
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

// Constructs standard 9-character POSIX permission string.
// Avoids locale-dependent formatting and ensures predictable column width.
std::string format_perms(const mode_t &mode) {
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

// Maps severity enum to fixed-width string for table alignment.
std::string_view format_severity(const kls::findings::SeverityFindings &severity) {
  switch (severity) {
  case kls::findings::SeverityFindings::None:
    return "NONE";
  case kls::findings::SeverityFindings::Low:
    return "LOW";
  case kls::findings::SeverityFindings::MedLow:
    return "MEDLOW";
  case kls::findings::SeverityFindings::Med:
    return "MED";
  case kls::findings::SeverityFindings::High:
    return "HIGH";
  case kls::findings::SeverityFindings::Crit:
    return "CRIT";
  }
  return "NONE";
}

namespace kls::report {

// ARCHITECTURAL NOTE: Renderer is strictly presentation.
// It does not filter, sort, or evaluate security rules. 
// It consumes the immutable `ScanOutput` model to prevent side effects.
void render_report(std::ostream &output, const kls::scanner::ScanOutput &entries, const kls::report::RenderOptions &option_render) {
  if (entries.items.empty()) {
    return;
  }

  // Local instantiation ensures state isolation per render call.
  kls::platform::IdentityResolver identity_resolver;

  if (option_render.show_headers) {
    output << std::format(
        "{:<5} {:<10} {:<8} {:<8} {:<12} {:<30} {:<10} {:<20}\n", 
        "TYPE", "PERMS", "OWNER", "GROUP", "MODIFIED", "NAME", "SEVERITY", "FINDING"
    );
  }
  
  output << std::string(120, '-') << "\n";

  // Range-based for loop avoids index management and clarifies intent.
  for (const auto &item : entries.items) {
    const auto &actual_entry = item.entry;
    
    std::string perms = format_perms(actual_entry.mode);
    
    // "yyyy-mm-dd" is exactly 10 chars + 1 null terminator.
    std::array<char, 11> str_time{};
    struct tm time_buffer{};
    
    if (gmtime_r(&actual_entry.mtime, &time_buffer) != nullptr) {
      std::strftime(str_time.data(), str_time.size(), "%F", &time_buffer);
    }

    std::string_view type_str = format_file_type(actual_entry.type);
    std::string_view formatted_name = actual_entry.name;

    output << std::format(
        "{:<5} {:<10} {:<8} {:<8} {:<12} {:<30} {:<10}\n", 
        type_str, 
        perms,
        identity_resolver.owners_name(actual_entry.uid),
        identity_resolver.groups_name(actual_entry.gid),
        std::string_view(str_time.data()), 
        formatted_name,
        format_severity(kls::findings::get_max_level_severity(item.findings))
    );
  }
}

} // namespace kls::report
