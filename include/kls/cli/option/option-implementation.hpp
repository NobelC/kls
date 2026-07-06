#pragma once
#include "option-raw-metadata.hpp"

void CreatedOptionData();
void GeneralOptionLog(const OptionMetaData& option);
const OptionMetaData* GetOptionData(std::string_view name_option);
