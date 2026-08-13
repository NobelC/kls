#include "kls/report/render_option.hpp"
#include "kls/report/render_report.hpp"
#include "kls/platform/identity_resolver.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/scanner/scanner.hpp"

#include <vector>
#include <string_view>
#include <array>
#include <format>
#include <ctime>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

  std::string conversion_type_file(const kls::filesystem::FileType& type){
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

namespace kls::report {

  void render_report(std::ostream& output,const kls::scanner::ScanOutput& entries, const kls::report::RenderOptions& option_render){

    kls::platform::IdentityResolver Identity;
    const auto maximum_name_width = option_render.maximum_name_width;
    if (entries.items.empty()) {
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

  for (size_t i = 0 ; i < entries.items.size() ; i++) {
    auto& actual_entry = entries.items[i].entry;
    // 1. Perms (Mode)
    std::string perms;
    perms += (actual_entry.mode & S_IRUSR) ? "r" : "-";
    perms += (actual_entry.mode & S_IWUSR) ? "w" : "-";
    perms += (actual_entry.mode & S_IXUSR) ? "x" : "-";
    
    perms += (actual_entry.mode & S_IRGRP) ? "r" : "-";
    perms += (actual_entry.mode & S_IWGRP) ? "w" : "-";
    perms += (actual_entry.mode & S_IXGRP) ? "x" : "-";

    perms += (actual_entry.mode & S_IROTH) ? "r" : "-";
    perms += (actual_entry.mode & S_IWOTH) ? "w" : "-";
    perms += (actual_entry.mode & S_IXOTH) ? "x" : "-";
    

     
    
    // 3. Time
    std::array<char, std::size("yyyy-mm-dd")> str_time{};
    struct tm time_buffer;
    
    if(gmtime_r(&actual_entry.mtime,&time_buffer) != nullptr){
      std::strftime(str_time.data(), str_time.size(), "%F", &time_buffer);
    }

    // 4. Size
    std::string size_str;
    auto size_final = static_cast<double>(actual_entry.size);
    if((actual_entry.size < 1024)){
      size_str = std::format("{:.2f} B",size_final);
    }
    else if(actual_entry.size < 1048576){
      size_final /= 1024.0;
      size_str = std::format("{:.2f} KB",size_final);
    }
    else if(actual_entry.size < 1073741824){
      size_final /= 1048576.0;
      size_str = std::format("{:.2f} MB",size_final);
    }
    else if(actual_entry.size < 1099511627776){
      size_final /= 1073741824.0;
      size_str = std::format("{:.2f} GB",size_final);
    }
    else{
      size_final /=  1099511627776.0;
      size_str = std::format("{:.2f} TB",size_final);   
    }
    
    std::string type;
    type.reserve(3);

    std::string display_name = actual_entry.full_path;
    if(maximum_name_width < display_name.size()){
      display_name.resize(maximum_name_width -3);
      display_name.append("...");
    }
    
    auto pading_size = maximum_name_width - static_cast<unsigned int>(display_name.size());
    std::string padding = pading_size > 0 ? std::string(pading_size, ' ') : "" ;

    std::string formatted_name;
    formatted_name.reserve(display_name.size());
    formatted_name.append(display_name).append(padding);
    type = conversion_type_file(actual_entry.type);
    // Color for directory name
    

    // Final Render
    output << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",type, perms,actual_entry.nlinks, 
                          Identity.owners_name(actual_entry.uid),Identity.groups_name(actual_entry.gid), 
                          size_str, std::string_view(str_time.data(), str_time.size()), formatted_name);
    formatted_name.clear();
    display_name.clear();
  }

}
}
