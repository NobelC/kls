#pragma once
#include <any>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <variant>
#include <vector>

enum class TypeDataReceived : std::uint8_t {
  DATE,     
  SIZE,    
  EXTENSION, 
  NONE,     
  STRING,
};

enum class OptionCategory : std::uint8_t {
  COLLECTION = 0,
  FILTERING =1, 
  SORTING = 2, 
  PRESENTATION = 3, 
  MANIPULATION =4, 
  CREATION = 5, 
  GLOBAL =6,
};

struct ID{
  private:
    uint32_t val;
  public:
  explicit constexpr ID(const char (&s)[5]) : val(
      (static_cast<uint32_t>(s[0]) << 24) |
      (static_cast<uint32_t>(s[1]) << 16) |
      (static_cast<uint32_t>(s[2]) << 8)  |
      (static_cast<uint32_t>(s[3])
      )){}

  explicit constexpr ID(std::string_view s) : val(
      s.size() != 4 ? throw "Error : Code size incorrecto" : 
      (static_cast<uint32_t>(s[0])) << 24 |
      (static_cast<uint32_t>(s[1])) << 16 |
      (static_cast<uint32_t>(s[2])) << 8  |
      (static_cast<uint32_t>(s[3]))
 ) {}
  
  [[nodiscard]] uint32_t get_value() const{
    return val;
  }

  bool operator==(const ID& other) const {return val == other.val;}
  
 [[nodiscard]] std::string to_string() const {
    const char buffer[4] = {
        static_cast<char>(val >> 24 & 0xFF),
        static_cast<char>(val >> 16 & 0xFF),
        static_cast<char>(val >> 8  & 0xFF),
        static_cast<char>(val       & 0xFF)
    };
    // El constructor std::string(ptr, count) no necesita \0
    return std::string(buffer, 4); 
}
};

struct HealthFlag {
  const char* message; 
  ID id;
  uint8_t level;
};

struct FileEntry {
  
  ino_t inode = 0;  
  uint64_t size = 0;  
  mode_t mode = 0;    
  nlink_t nlinks = 0; 
  uid_t uid = 0;      
  gid_t gid = 0;   

  
  bool is_directory : 1 = false;
  bool is_symlink : 1 = false;
  bool symlink_broken : 1 = false;
  bool has_capabilities : 1 = false;
  bool correct_state : 1 = false;

 
  time_t mtime = 0;
  time_t btime = 0; 

  std::string name;
  std::string path;
  std::string symlink_target;
  std::string extension;
  std::vector<HealthFlag> health;

  FileEntry() noexcept
  {
    name.reserve(256);
    path.reserve(256);
    symlink_target.reserve(256);
    extension.reserve(256);
    health.reserve(2);
  }


  void clear() noexcept {
    inode = 0;
    size = 0;
    mode = 0;
    nlinks = 0;
    uid = 0;
    gid = 0;
    is_directory = false;
    is_symlink = false;
    symlink_broken = false;
    has_capabilities = false;
    mtime = 0;
    btime = 0;
    correct_state = false;
    name.clear();
    path.clear();
    symlink_target.clear();
    extension.clear();
    health.clear();
  }
};

struct FilterStruct {
  std::vector<FileEntry> &entries;
  std::any context; 
};

struct PresentationStruct {
  std::vector<FileEntry> &entries;
};

using FilteringProcess = std::function<void(FilterStruct &)>;
using PresentationProcess = std::function<void(PresentationStruct &,
                                      std::unordered_map<uid_t,std::string>& ,
                                      std::unordered_map<uid_t,std::string>&)>;
using GlobalOptionProcess = std::function<void(std::string_view& )>;


using OptionHandler =
    std::variant<std::monostate,                          
                 FilteringProcess,    
                 PresentationProcess,
                 GlobalOptionProcess
                 >;

struct OptionMetaData {
  std::string normalized_name;
  std::string alias_name;
  std::vector<std::string> conflict_name;
  std::vector<std::string> requieres_name = {};
  TypeDataReceived data_type = TypeDataReceived::NONE;
  OptionCategory category;
  OptionHandler hanlder;
};
