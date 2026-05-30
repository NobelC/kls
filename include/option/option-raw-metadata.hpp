#pragma once
#include <any>
#include <cstdint>
#include <functional>
#include <string>
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


struct HealthFlag {
  std::string code; 
  uint8_t level;    
};

struct FileEntry {
  
  ino_t inode;  
  uint64_t size;  
  mode_t mode;    
  nlink_t nlinks; 
  uid_t uid;      
  gid_t gid;   

  
  bool is_directory : 1;
  bool is_symlink : 1;
  bool symlink_broken : 1;
  bool has_capabilities : 1;

 
  time_t mtime;
  time_t btime; 

  std::string name;
  std::string path;
  std::string symlink_target;
  std::string extension;
  std::vector<HealthFlag> health;
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

using OptionHandler =
    std::variant<std::monostate,                          
                 FilteringProcess,    
                 PresentationProcess 
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
