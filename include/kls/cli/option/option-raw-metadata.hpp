#pragma once
#include <any>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <variant>
#include <vector>
#include "../../audit/audit_entry.hpp"

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


struct FilterStruct {
  std::vector<kls::audit::AuditEntry> &entries;
  std::any context; 
};

struct PresentationStruct {
  std::vector<kls::audit::AuditEntry> &entries;
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
  OptionHandler handler;
};
