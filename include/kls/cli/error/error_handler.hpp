#pragma once
#include <string_view>
#include "../option/option-raw-metadata.hpp"

void COMMAND_NOT_FOUND(std::string_view trigger);
void OPTION_NOT_FOUND(std::string_view trigger);
void OPTION_NEED_VALUE(std::string_view trigger,const TypeDataReceived& type_data);
void OPTION_NOT_AVAIBLE_FOR_COMMAND(std::string_view trigger,std::string_view command);
void OPTION_CONFLICT_WITH(std::string_view trigger);
void INCORRECT_NUMBER_OF_POSITIONAL_NUMBER(std::string_view command, const int& number , const int& min , const int& max);
void OPTION_REQUIERES_OPTION(std::string_view option,std::string_view requieres);
void DEFAULT_VALUE_OPTION(std::string_view option, const int& default_value);
void EQUAL_DIRECTION();
void ORIGIN_DIRECTORY_NOT_VALITED(std::string_view dir);

