#include <kls/report/report_render.hpp>

// Estándar C++ (Mínimo C++20 por <format>)
#include <vector>
#include <string_view>
#include <array>
#include <format>
#include <iostream>
#include <numeric>
#include <ctime>
#include <cerrno>

// APIs del Sistema POSIX
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

constexpr unsigned int MAX_LENGTH = 30;

void kls::report::render_report(std::ostream output,std::span<const kls::audit::AuditEntry> &entries, const int &option_bool){
    if (entries.empty()) {
    return;
  }

  if(option_bool.no_header_format ){

  }
  else if(option_bool.no_health){
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME");
  }
  else{
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME", "ALERTS");
  }
  std::cout << std::string(120, '-') << "\n";

  for (auto &e : entries) {
    auto AddFlag = [&](ID id) {
        const HealthFlag* flag = GetHealthFlag(id);
        if (flag) { e.health.emplace_back(*flag); }
    };

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
    

    
    std::string owner;
    {
      if(cache_owner.contains(e.uid)){
        owner = cache_owner.at(e.uid);
      }
      else{
        errno = 0;
        const passwd* pw = getpwuid(e.uid);
        if(pw){
          cache_owner[e.uid] = pw->pw_name;
          owner = pw->pw_name;
        }
        else{
          cache_owner[e.uid] = std::to_string(e.uid);
          if(!option_bool.no_health){ 
            if(errno == 0 || errno == ENOENT){
              AddFlag(ID("SU23"));
            }
          }
        }
      }
    }
    std::string group_str;
    {
      if(cache_group.contains(e.gid)){
        group_str = cache_group.at(e.gid);
      }
      else{
        errno = 0;
        const group* gp = getgrgid(e.gid);
        if(gp){
          cache_group[e.gid] = gp->gr_name;
          group_str = gp->gr_name;
        }
        else{
          cache_group[e.gid] = std::to_string(e.gid);
          if(!option_bool.no_health){
            if(errno == 0 || errno == ENOENT){
              AddFlag(ID("SU24"));
            }
          }
        }
      }
    }
    

    // 3. Time
    std::array<char, std::size("yyyy-mm-dd")> str_time;
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
    if(MAX_LENGTH < display_name.size()){
      display_name.resize(MAX_LENGTH -3);
      display_name.append("...");
    }
    
    auto pading_size = MAX_LENGTH - static_cast<unsigned int>(display_name.size());
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
    if(option_bool.no_health){
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",type, perms,
                             e.nlinks, owner, group_str, size_str, std::string_view(str_time.data(), str_time.size()), formatted_name);
    }
    else{
      auto join_alert = std::accumulate(e.health.begin(), e.health.end(), std::string{},
        [](const std::string& acc, const HealthFlag& s){
          return acc.empty() ? s.id.to_string() : acc + " | " + s.id.to_string(); 
        });
      if (join_alert.empty()){
        join_alert = "-----------";
      }
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n", type, perms,
                             e.nlinks, owner, group_str, size_str, std::string_view(str_time.data(), str_time.size()), formatted_name, join_alert);
    }
    formatted_name.clear();
    display_name.clear();
  }

}
