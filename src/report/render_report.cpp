#include "../../include/kls/report/render_option.hpp"
#include "../../include/kls/report/render_report.hpp"
#include "../../include/kls/platform/identity_resolver.hpp"

#include <vector>
#include <string_view>
#include <array>
#include <format>
#include <numeric>
#include <ctime>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

namespace kls::report {

  void render_report(std::ostream& output,std::span<const kls::audit::AuditEntry> entries, const kls::report::RenderOptions& option_render){

    kls::platform::IdentityResolver Identity;
    const auto maximum_name_width = option_render.maximum_name_width;
    if (entries.empty()) {
      return;
    }

  if(!option_render.show_headers){

  }
  else if(!option_render.show_findings){
      output << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME");
  }
  else{
      output << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME", "ALERTS");
  }
  output << std::string(120, '-') << "\n";

  for (const auto &e : entries) {

    // 1. Perms (Mode)
    std::string perms;
    perms += (e.mode & S_IRUSR) ? "r" : "-";
    perms += (e.mode & S_IWUSR) ? "w" : "-";
    perms += (e.mode & S_IXUSR) ? "x" : "-";
    
    perms += (e.mode & S_IRGRP) ? "r" : "-";
    perms += (e.mode & S_IWGRP) ? "w" : "-";
    perms += (e.mode & S_IXGRP) ? "x" : "-";

    perms += (e.mode & S_IROTH) ? "r" : "-";
    perms += (e.mode & S_IWOTH) ? "w" : "-";
    perms += (e.mode & S_IXOTH) ? "x" : "-";
    

     
    
    // 3. Time
    std::array<char, std::size("yyyy-mm-dd")> str_time{};
    struct tm time_buffer;
    
    if(gmtime_r(&e.mtime,&time_buffer) != nullptr){
      std::strftime(str_time.data(), str_time.size(), "%F", &time_buffer);
    }

    // 4. Size
    std::string size_str;
    auto size_final = static_cast<double>(e.size);
    if((e.size < 1024)){
      size_str = std::format("{:.2f} B",size_final);
    }
    else if(e.size < 1048576){
      size_final /= 1024.0;
      size_str = std::format("{:.2f} KB",size_final);
    }
    else if(e.size < 1073741824){
      size_final /= 1048576.0;
      size_str = std::format("{:.2f} MB",size_final);
    }
    else if(e.size < 1099511627776){
      size_final /= 1073741824.0;
      size_str = std::format("{:.2f} GB",size_final);
    }
    else{
      size_final /=  1099511627776.0;
      size_str = std::format("{:.2f} TB",size_final);   
    }
    
    std::string type;
    type.reserve(3);

    std::string display_name = e.name;
    if(maximum_name_width < display_name.size()){
      display_name.resize(maximum_name_width -3);
      display_name.append("...");
    }
    
    auto pading_size = maximum_name_width - static_cast<unsigned int>(display_name.size());
    std::string padding = pading_size > 0 ? std::string(pading_size, ' ') : "" ;

    std::string formatted_name;
    formatted_name.reserve(display_name.size());
    // Color for directory name
    if(e.is_directory){
      formatted_name.append(display_name).append(padding);
      type = "DIR";
    } 
    else{
      formatted_name.append(display_name);
      type = e.is_symlink ? "SYM" : "FIL";
    }

    // Final Render
    if(!option_render.show_findings){
      output << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",type, perms,
                             e.nlinks, Identity.owners_name(e.uid),Identity.groups_name(e.gid), size_str, std::string_view(str_time.data(), str_time.size()), formatted_name);
    }
    else{
      auto join_alert = std::accumulate(e.health.begin(), e.health.end(), std::string{},
        [](std::string acc, const auto& finding){
          if(!acc.empty()){
            acc += " | ";
          }
          acc += finding.id.to_string();
          return acc;
        });
      if (join_alert.empty()){
        join_alert = "-----------";
      }
      output << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n", type, perms,
                             e.nlinks, Identity.owners_name(e.uid),Identity.groups_name(e.gid), size_str, std::string_view(str_time.data(), str_time.size()), formatted_name, join_alert);
    }
    formatted_name.clear();
    display_name.clear();
  }

}
}
