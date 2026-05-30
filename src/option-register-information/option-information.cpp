#include "../../include/option/option-implementation.hpp"
#include "../../include/option/option-raw-metadata.hpp"
#include "../../include/token/token-raw-metadata.hpp"
#include <algorithm>
#include <any>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fnmatch.h>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <system_error>
#include <tuple>
#include <unordered_set>
#include <vector>
#include <pwd.h>
#include <grp.h>
#include <iostream>
#include <format>
#include <string>

namespace {
std::string FormatTime(const std::time_t &time) {
  std::array<char, 20> buffer;
  const auto *tm_ptr = std::localtime(&time);
  if (tm_ptr &&
      std::strftime(buffer.data(), sizeof(buffer), "%Y-%m-%d", tm_ptr)) {
    return {buffer.data()};
  }
  return "0000-00-00";
}

uint64_t FormatSize(const std::string_view size) {
  if (size.empty()) {
    return 0;
  }
  uint64_t digits = 0;
  auto [ptr, ec] =
      std::from_chars(size.data(), size.data() + size.size(), digits);

  if (ec == std::errc::result_out_of_range) {
    return UINT64_MAX;
  }
  if (ec != std::errc{} || ptr == size.data()) {
    return 0;
  }

  std::string_view sufix(ptr, size.data() + size.size());
  uint64_t multiplier = 1;

  if (sufix.empty()) {
    multiplier = 1024ULL * 1024;
    if (digits > UINT64_MAX / multiplier) {
      return UINT64_MAX;
    }
    return digits * multiplier;
  }

  if (sufix == "B" || sufix == "b") {
    multiplier = 1;
  } else if (sufix == "KB" || sufix == "kb") {
    multiplier = 1024ULL;
  } else if (sufix == "MB" || sufix == "mb") {
    multiplier = 1024ULL * 1024;
  } else if (sufix == "GB" || sufix == "gb") {
    multiplier = 1024ULL * 1024 * 1024;
  } else if (sufix == "TB" || sufix == "tb") {
    multiplier = 1024ULL * 1024 * 1024 * 1024;
  } else {
    return 0;
  }

  if (digits > UINT64_MAX / multiplier) {
    return UINT64_MAX;
  }

  return digits * multiplier;
}

} // namespace

void CreatedOptionData() {
  // --- GLOBAL OPTIONS ---

  OptionMetaData help;
  help.normalized_name = "--help";
  help.alias_name = "-h";
  help.data_type = TypeDataReceived::NONE;
  help.category = OptionCategory::GLOBAL;
  help.hanlder = std::monostate{};
  GeneralOptionLog(help);

  OptionMetaData version;
  version.normalized_name = "--version";
  version.alias_name = "-v";
  version.data_type = TypeDataReceived::NONE;
  version.category = OptionCategory::GLOBAL;
  version.hanlder = std::monostate{};
  GeneralOptionLog(version);

  OptionMetaData no_color;
  no_color.normalized_name = "--no-color";
  no_color.data_type = TypeDataReceived::NONE;
  no_color.category = OptionCategory::GLOBAL;
  no_color.hanlder = std::monostate{};
  GeneralOptionLog(no_color);

  OptionMetaData quiet;
  quiet.normalized_name = "--quiet";
  quiet.alias_name = "-q";
  quiet.conflict_name = {"--verbose"};
  quiet.data_type = TypeDataReceived::NONE;
  quiet.category = OptionCategory::GLOBAL;
  quiet.hanlder = std::monostate{};
  GeneralOptionLog(quiet);

  OptionMetaData verbose;
  verbose.normalized_name = "--verbose";
  verbose.conflict_name = {"--quiet"};
  verbose.data_type = TypeDataReceived::NONE;
  verbose.category = OptionCategory::GLOBAL;
  verbose.hanlder = std::monostate{};
  GeneralOptionLog(verbose);

  // --- RECOLECCIÓN Y FILTRADO ---

  OptionMetaData all;
  all.normalized_name = "--all";
  all.alias_name = "-a";
  all.conflict_name = {"--no-hidden"};
  all.data_type = TypeDataReceived::NONE;
  all.category = OptionCategory::COLLECTION;
  all.hanlder = std::monostate{};
  GeneralOptionLog(all);

  OptionMetaData recursive;
  recursive.normalized_name = "--recursive";
  recursive.alias_name = "-r";
  recursive.data_type = TypeDataReceived::NONE;
  recursive.category = OptionCategory::COLLECTION;
  recursive.hanlder = std::monostate{};
  GeneralOptionLog(recursive);

  OptionMetaData depth;
  depth.normalized_name = "--depth";
  depth.alias_name = "-d";
  depth.requieres_name = {"--recursive"};
  depth.data_type = TypeDataReceived::STRING;
  depth.category = OptionCategory::FILTERING;
  GeneralOptionLog(depth);

  OptionMetaData filter;
  filter.normalized_name = "--filter";
  filter.data_type = TypeDataReceived::EXTENSION;
  filter.category = OptionCategory::FILTERING;
  filter.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *pattern_sv_ptr =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!pattern_sv_ptr) {
      return;
    }

    std::string pattern(*pattern_sv_ptr);
    std::erase_if(filter_contex.entries, [&pattern](const FileEntry &e) {
      return fnmatch(pattern.c_str(), e.name.c_str(), 0) != 0;
    });
  });
  GeneralOptionLog(filter);

  OptionMetaData modified_before;
  modified_before.normalized_name = "--modified-before";
  modified_before.data_type = TypeDataReceived::DATE;
  modified_before.category = OptionCategory::FILTERING;

  modified_before.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *date_ptr =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!date_ptr) {
      return;
    }

    const std::string_view &target_date = *date_ptr;
    std::erase_if(filter_contex.entries, [&target_date](const FileEntry &e) {
      const auto &file_date = FormatTime(e.mtime);
      return file_date >= target_date;
    });
  });

  GeneralOptionLog(modified_before);

  OptionMetaData modified_after;
  modified_after.normalized_name = "--modified-after";
  modified_after.data_type = TypeDataReceived::DATE;
  modified_after.category = OptionCategory::FILTERING;
  modified_after.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *date_ptr =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!date_ptr) {
      return;
    }

    const std::string_view &target_date = *date_ptr;
    std::erase_if(filter_contex.entries, [&target_date](const FileEntry &e) {
      const auto &file_date = FormatTime(e.mtime);
      return file_date <= target_date;
    });
  });
  GeneralOptionLog(modified_after);

  OptionMetaData dirs_only;
  dirs_only.normalized_name = "--dirs-only";
  dirs_only.data_type = TypeDataReceived::NONE;
  dirs_only.category = OptionCategory::FILTERING;
  dirs_only.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    std::erase_if(filter_contex.entries,
                  [](const FileEntry &e) { return !e.is_directory; });
  });
  GeneralOptionLog(dirs_only);

  OptionMetaData file_only;
  file_only.normalized_name = "--file-only";
  file_only.data_type = TypeDataReceived::NONE;
  file_only.category = OptionCategory::FILTERING;
  file_only.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    std::erase_if(filter_contex.entries, [](const FileEntry &e) {
      return (e.is_directory || e.is_symlink);
    });
  });
  GeneralOptionLog(file_only);

  OptionMetaData extension;
  extension.normalized_name = "--ext";
  extension.data_type = TypeDataReceived::EXTENSION;
  extension.category = OptionCategory::FILTERING;
  extension.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *extension_raw =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!extension_raw) {
      return;
    }

    const std::string_view ext = *extension_raw;
    if (ext.empty()) {
      return;
    }

    std::unordered_set<std::string_view, transparent_hash, std::equal_to<>>
        table_extension;
    size_t start = 0;
    size_t end = 0;

    while ((end = ext.find(',', start)) != std::string_view::npos) {
      if (end > start) {
        std::string_view token = ext.substr(start, end - start);
        if (token.starts_with('.')) {
          token.remove_prefix(1);
        }
        table_extension.insert(token);
      }
      start = end + 1;
    }
    if (start < ext.length()) {
      std::string_view token = ext.substr(start);
      if (token.starts_with('.')) {
        token.remove_prefix(1);
      }
      table_extension.insert(token);
    }

    std::erase_if(filter_contex.entries,
                  [&table_extension](const FileEntry &e) {
                    if (e.extension.empty()) {
                      return true;
                    }
                    return !table_extension.contains(e.extension.substr(1));
                  });
  });
  GeneralOptionLog(extension);

  OptionMetaData larger_than;
  larger_than.normalized_name = "--larger-than";
  larger_than.data_type = TypeDataReceived::SIZE;
  larger_than.category = OptionCategory::FILTERING;
  larger_than.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *size_raw =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!size_raw) {
      return;
    }

    const std::string_view size_num = *size_raw;
    if (size_num.empty()) {
      return;
    }

    const auto size = FormatSize(size_num);

    std::erase_if(filter_contex.entries,
                  [&size](const FileEntry &e) { return !(size <= e.size); });
  });
  GeneralOptionLog(larger_than);

  OptionMetaData smaller_than;
  smaller_than.normalized_name = "--smaller-than";
  smaller_than.data_type = TypeDataReceived::SIZE;
  smaller_than.category = OptionCategory::FILTERING;
  smaller_than.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *size_raw =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!size_raw) {
      return;
    }

    const std::string_view size_num = *size_raw;
    if (size_num.empty()) {
      return;
    }

    const auto size = FormatSize(size_num);

    std::erase_if(filter_contex.entries,
                  [&size](const FileEntry &e) { return !(size >= e.size); });
  });
  GeneralOptionLog(smaller_than);


OptionMetaData owner_filter;
owner_filter.normalized_name = "--owner";
owner_filter.data_type = TypeDataReceived::STRING;
owner_filter.category = OptionCategory::FILTERING;
owner_filter.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
  const auto *owner_raw = std::any_cast<std::string_view>(&filter_contex.context);
  if (!owner_raw || owner_raw->empty()) {
    return;
  }

  const std::string_view owner = *owner_raw;
  static std::unordered_map<uid_t, std::string> cache_owner; 

  std::erase_if(filter_contex.entries, [&](const FileEntry &e) {
    auto it = cache_owner.find(e.uid);
    if (it == cache_owner.end()) {
      const struct passwd *pw = getpwuid(e.uid);
      it = cache_owner.insert({e.uid, pw ? std::string(pw->pw_name) : "UNKNOWN"}).first;
    }
    return it->second != owner;
  });
});
GeneralOptionLog(owner_filter);
  
  OptionMetaData group_filter;
  group_filter.normalized_name = "--group"; 
  group_filter.data_type = TypeDataReceived::STRING;
  group_filter.category = OptionCategory::FILTERING;
  group_filter.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
  const auto *group_raw = std::any_cast<std::string_view>(&filter_contex.context);
  if (!group_raw || group_raw->empty()) {
    return;
  }

  const std::string_view group = *group_raw;
  static std::unordered_map<gid_t, std::string> cache_group; 

  std::erase_if(filter_contex.entries, [&](const FileEntry &e) {
    auto it = cache_group.find(e.gid);
    if (it == cache_group.end()) {
      const struct group *gp = getgrgid(e.gid); 
      it = cache_group.insert({e.gid, gp ? std::string(gp->gr_name) : "UNKNOWN"}).first;
    }
    return it->second != group;
    });
  });
  GeneralOptionLog(group_filter);

  OptionMetaData min_links;
  min_links.normalized_name = "--min-links"; 
  min_links.data_type = TypeDataReceived::STRING;
  min_links.category = OptionCategory::FILTERING;
  min_links.hanlder = FilteringProcess([](FilterStruct &filter_contex){
      const auto* min_link_raw = std::any_cast<std::string_view>(&filter_contex.context);
      if(!min_link_raw || min_link_raw->empty()){
        return;
      }
      nlink_t n_link = 0;
      auto [ptr,ercc] = std::from_chars(min_link_raw->data(), min_link_raw->data() + min_link_raw->size(), n_link);
      if(ercc != std::errc{}){
        return;
      }
      std::erase_if(filter_contex.entries, [n_link](const FileEntry& e){
          return n_link > e.nlinks; 
          });
      });
  GeneralOptionLog(min_links);

  OptionMetaData min_severity;
  min_severity.normalized_name = "--min-severity"; 
  min_severity.data_type = TypeDataReceived::STRING;
  min_severity.category = OptionCategory::FILTERING;
  min_severity.hanlder = FilteringProcess([](FilterStruct &filter_contex){
      const auto* min_severity_raw = std::any_cast<std::string_view>(&filter_contex.context);
      if(!min_severity_raw || min_severity_raw->empty()){
        return;
      }
      uint8_t min_severity_value = 0;
      auto [ptr,ercc] = std::from_chars(min_severity_raw->data(), min_severity_raw->data() + min_severity_raw->size(), min_severity_value);
      if(ercc != std::errc{}){
        return;
      }

      std::erase_if(filter_contex.entries, [min_severity_value](const FileEntry& e){
          bool has_high_severity  =  std::ranges::any_of(e.health, [min_severity_value](uint8_t lvl){
                return lvl >= min_severity_value;
              }, &HealthFlag::level);
          return !has_high_severity;
          });
      });
  GeneralOptionLog(min_severity);

  // --- ORDENAMIENTO (SORTING) ---

  OptionMetaData sort;
  sort.normalized_name = "--sort";
  sort.data_type = TypeDataReceived::STRING;
  sort.category = OptionCategory::SORTING;
  sort.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    const auto *criteria_ptr =
        std::any_cast<std::string_view>(&filter_contex.context);
    if (!criteria_ptr) {
      return;
    }

    std::string criteria(*criteria_ptr);
    if (criteria == "name") {
      std::ranges::sort(filter_contex.entries,
                        [](const FileEntry &a, const FileEntry &b) {
                          return a.name < b.name;
                        });
    } else if (criteria == "size") {
      std::ranges::sort(
          filter_contex.entries, [](const FileEntry &a, const FileEntry &b) {
            // Tamaño descendente, desempate por nombre
            return std::tie(b.size, a.name) < std::tie(a.size, b.name);
          });
    } else if (criteria == "type") {
      std::ranges::sort(filter_contex.entries,
                        [](const FileEntry &a, const FileEntry &b) {
                          // Directorios primero (true > false)
                          return std::tie(b.is_directory, a.name) <
                                 std::tie(a.is_directory, b.name);
                        });
    } else if (criteria == "modified") {
      std::ranges::sort(
          filter_contex.entries, [](const FileEntry &a, const FileEntry &b) {
            return std::tie(a.mtime, a.name) < std::tie(b.mtime, b.name);
          });
    } else if (criteria == "ext" || criteria == "extension") {
      std::ranges::sort(filter_contex.entries, [](const FileEntry &a,
                                                  const FileEntry &b) {
        return std::tie(a.extension, a.name) < std::tie(b.extension, b.name);
      });
    } else if (criteria == "severity") {
      std::ranges::sort(filter_contex.entries,std::ranges::greater(),
                        [](const FileEntry &entry) {
                          auto it = std::ranges::max_element(entry.health, {}, &HealthFlag::level);
                          return it == entry.health.end()? 0 : it->level;
                        });
    }
  });
  GeneralOptionLog(sort);
  
  OptionMetaData alerts_first;
  alerts_first.normalized_name = "--alerts-first";
  alerts_first.category = OptionCategory::SORTING;
  alerts_first.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    std::ranges::sort(filter_contex.entries,std::ranges::greater(),
                      [](const FileEntry &entry) {
                        auto it = std::ranges::max_element(entry.health, {}, &HealthFlag::code);
                        return it == entry.health.end() ? "" : it->code;
                      });
  });
  GeneralOptionLog(alerts_first);



  OptionMetaData reverse;
  reverse.normalized_name = "--reverse";
  reverse.category = OptionCategory::SORTING;
  reverse.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    std::ranges::reverse(filter_contex.entries);
  });
  GeneralOptionLog(reverse);

  OptionMetaData dirs_first;
  dirs_first.normalized_name = "--dirs-first";
  dirs_first.category = OptionCategory::SORTING;
  dirs_first.hanlder = FilteringProcess([](FilterStruct &filter_contex) {
    std::ranges::sort(filter_contex.entries,
                      [](const FileEntry &a, const FileEntry &b) {
                        return std::tie(b.is_directory, a.name) <
                               std::tie(a.is_directory, b.name);
                      });
  });
  GeneralOptionLog(dirs_first);

  // --- PRESENTACIÓN ---

  OptionMetaData no_header;
  no_header.normalized_name = "--no-header";
  no_header.category = OptionCategory::PRESENTATION;
  no_header.hanlder = std::monostate{};
  GeneralOptionLog(no_header);

  OptionMetaData stats;
  stats.normalized_name = "--stats";
  stats.category = OptionCategory::PRESENTATION;
  stats.hanlder = std::monostate{};
  GeneralOptionLog(stats);

  // --- SEGURIDAD ---

  OptionMetaData health;
  health.normalized_name = "--health";
  health.category = OptionCategory::PRESENTATION;
  health.hanlder = std::monostate{};
  GeneralOptionLog(health);

  OptionMetaData no_health;
  no_health.normalized_name = "--no-health";
  no_health.category = OptionCategory::PRESENTATION;
  no_health.hanlder = PresentationProcess([](PresentationStruct& entries,std::unordered_map<uid_t, std::string>& owner_group,std::unordered_map<uid_t, std::string>& cache_group)
      {
        std::cout << std::format("{:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",
                           "PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME");
        std::cout << std::string(120, "-") << "\n";
        for(const auto& e : entries){
          std::string perms;
        }


      });
  GeneralOptionLog(no_health);

  OptionMetaData only_alerts;
  only_alerts.normalized_name = "--only-alerts";
  only_alerts.category = OptionCategory::FILTERING;
  only_alerts.hanlder = std::monostate{};
  GeneralOptionLog(only_alerts);

}
