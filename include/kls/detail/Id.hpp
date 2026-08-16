#pragma once
#include <cstdint>
#include <string_view>
#include <string>
#include <array>
#include <stdexcept>

struct ID {
private:
    uint32_t val;
    static constexpr uint32_t pack(const char* s) noexcept {
        return (static_cast<uint32_t>(s[0]) << 24) |
               (static_cast<uint32_t>(s[1]) << 16) |
               (static_cast<uint32_t>(s[2]) << 8)  |
               (static_cast<uint32_t>(s[3]));
    }

public:

    constexpr ID() noexcept : val(0) {} 
    constexpr explicit ID(const char(&s)[5]) noexcept : val(pack(s)) {}
    constexpr explicit ID(std::string_view s) : val(
        s.size() != 4 ? throw std::invalid_argument("Error: Code size incorrect") : pack(s.data())
    ) {}
  
    [[nodiscard]] constexpr uint32_t get_value() const noexcept {
        return val;
    }

    constexpr bool operator==(const ID& other) const noexcept {
        return val == other.val;
    } 
};
