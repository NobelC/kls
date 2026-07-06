#pragma once
#include "command-raw-metadata.hpp"
#include <string_view>

void CreatedCommandData();
void GeneralCommandLog(const CommandMetaData& command);
const CommandMetaData* GetCommandData(std::string_view command);
