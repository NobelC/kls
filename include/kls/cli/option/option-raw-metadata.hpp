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
  explicit constexpr ID(const std::array<char,5>&s) : val(
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
    const std::array<char,4>buffer = {
        static_cast<char>(val >> 24 & 0xFF),
        static_cast<char>(val >> 16 & 0xFF),
        static_cast<char>(val >> 8  & 0xFF),
        static_cast<char>(val       & 0xFF)
    };
    return {buffer.data(), 4};// The std::string(ptr, count) constructor does not need a null terminator 
}
};

struct HealthFlag {
  const char* message; 
  ID id;
  uint8_t level;
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
  OptionHandler handler;
};
