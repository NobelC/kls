#include "capabilities-register.hpp"
#include <iostream>

void PrintHealthFlags(const ID& id) {
    const kls::findings::HealthFlags* flag = GetCapabilityFlag(id);
    
    if (flag == nullptr) {
        std::cout << "[WARN] Health Flag ID non-existent: " << id.get_value() << "\n";
        return;
    }

    const char* level_str;

    switch (flag->level) {
        case 1:  level_str = "LOW" ;     break;
        case 2:  level_str = "INFO";     break;
        case 3:  level_str = "WARNING";  break;
        case 4:  level_str = "HIGH";     break;
        case 5:  level_str = "CRITICAL"; break;
        default: level_str = "UNKNOWN";
    }

    std::cout << "[SYSTEM HEALTH ALERT]\n"
              << " ├─ ID       : " << id.get_value() << "\n"
              << " ├─ Severity : " << level_str << "\n"
              << " └─ Message  : " << flag->message << "\n\n";
}
