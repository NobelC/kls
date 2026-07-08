#pragma once
#include <cstdint>
#include <sys/types.h>
#include <array>
#include <string_view>
#include <string>

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

