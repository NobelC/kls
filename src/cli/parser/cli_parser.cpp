#include "kls/cli/parser/cli_parser.hpp"
#include "kls/cli/model/cli_error.hpp"
#include "kls/cli/model/parser_options.hpp"
#include "kls/cli/spec/cli_spec.hpp"
#include "kls/cli/spec/option_spec.hpp"
#include "kls/result.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

namespace kls::cli::parser{ 
  namespace {
    const spec::OptionSpec* find_spec(std::string_view name_or_alias){
      if(name_or_alias.starts_with("--")){
        auto it = std::ranges::lower_bound(
        spec::CLI_SPECS,
        name_or_alias,
        {},
        &spec::OptionSpec::name
        );
        if(it != spec::CLI_SPECS.end() && it->name == name_or_alias){
          return &(*it);
        }
      }
      else if(name_or_alias.starts_with("-")){
        auto it = std::ranges::lower_bound(
          spec::CLI_ALIAS,
          name_or_alias,
          {},
          &spec::AliasIndex::alias
        );
        if(it != spec::CLI_ALIAS.end() && it->alias == name_or_alias){
          return &spec::CLI_SPECS[(it->spec_index)];
        }
      }
      return nullptr;
    }
    
    bool is_valid_date(std::string_view date){
      if(date.size() != 10){return false;}
      if(date[4] != '-' || date[7] != '-') {return false;}
      for(size_t i = 0 ; i < 10 ; ++i){
        if(i == 4 || i == 7) {continue;}
        if(!std::isdigit(static_cast<unsigned char>(date[i]))) {return false;}
      }
      return true;
    }

    bool is_valid_size(std::string_view size){
      if(size.empty()) {return false;}
      size_t i = 0;
      while(i < size.size() && std::isdigit(static_cast<unsigned char>(size[i]))) {++i;}
      if(i == 0) {return false;}
      if(i == size.size()) {return true;}
      auto unit = size.substr(i);
      static constexpr std::array<std::string_view,10> valid_units = {
        "B", "KB", "MB", "GB", "TB",
            "b", "kb", "mb", "gb", "tb"
      };
      return std::ranges::any_of(valid_units, [unit](auto u){
        return u == unit;
      });
    }

    bool is_valid_integer(std::string_view v) {
      if (v.empty()) {return false;}
      size_t start = (v[0] == '-') ? 1 : 0;
      if(start >= v.size()){return false;}
      return std::ranges::all_of(v.substr(start), [](unsigned char c){
        return std::isdigit(c);
      });
    } 

    model::CliError make_error(model::ErrorCode code, std::string_view option,
                               std::string_view message, std::string expected = "", 
                               std::string_view actual = ""){
      return {
        .code = code,
        .option_name = std::string(option),
        .conflicting_with = "",
        .expected_value = std::move(expected),
        .actual_value = std::string(actual),
        .message = std::string(message),
      };
    }

    model::CliError validate_value(const spec::OptionSpec& spec, std::string_view value) {
      switch (spec.value_type) {
        
        case spec::ValueType::NONE:
          return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Option does not accept a value", "", value);
        break;    
        
        case spec::ValueType::STRING:
          if (value.empty()) {return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Expected non-empty string", "non-empty", value);}
        break;
        
        case spec::ValueType::INTEGER:
          if (!is_valid_integer(value)){return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Expected integer value", "integer", value);}
        break;

        case spec::ValueType::DATE:
          if (!is_valid_date(value)){return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Expected date YYYY-MM-DD", "YYYY-MM-DD", value);}
        break;
        
        case spec::ValueType::SIZE:
          if (!is_valid_size(value)){return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Expected size (e.g. 1024MB)", "NUMBER[UNIT]", value);}
        break;

        case spec::ValueType::PATTERN:
          if (value.empty()){return make_error(model::ErrorCode::INVALID_VALUE, spec.name, "Expected non-empty pattern", "non-empty", value);}
        break;
      }
      return {};
    }
    
    void set_flag(model::ParsedOptions& opts, std::string_view name) {
      if      (name == "--help" || name == "-H")           {opts.help = true;}
      else if (name == "--version" || name == "-V")        {opts.version = true;}
      else if (name == "--no-color")                       {opts.no_color = true;}
      else if (name == "--quiet" || name == "-q")          {opts.quiet = true;}
      else if (name == "--verbose")                        {opts.verbose = true;}
      else if (name == "--all" || name == "-a")            {opts.all = true;}
      else if (name == "--recursive" || name == "-r")      {opts.recursive = true;}
      else if (name == "--only-findings")                  {opts.only_findings = true;}
      else if (name == "--reverse")                        {opts.reverse = true;}
      else if (name == "--dirs-first")                     {opts.dirs_first = true;}
      else if (name == "--findings-first")                 {opts.findings_first = true;}
      else if (name == "--long" || name == "-l")           {opts.long_format = true;}
      else if (name == "--no-header")                      {opts.no_header = true;}
    }

    model::CliError set_value(model::ParsedOptions& opts,const spec::OptionSpec& spec,std::string_view value) {
      std::string val(value);

      if (spec.name == "--depth" || spec.alias == "-d") {
        int32_t v = 0;
        auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), v);
        if (ec != std::errc()) {
            return make_error(model::ErrorCode::INVALID_VALUE, spec.name,"Failed to parse integer", "integer", value);
        }
        opts.depth = v;
      }
      else if (spec.name == "--filter")          {opts.filter = val;}
      else if (spec.name == "--modified-before") {opts.modified_before = val;}
      else if (spec.name == "--modified-after")  {opts.modified_after = val;}
      else if (spec.name == "--min-severity")    {opts.min_severity = val;}
      else if (spec.name == "--sort")            {opts.sort = val;}

      return {};
    }

    [[nodiscard]] std::optional<model::CliError> handle_double_dash(ArgvView argv, size_t& i, bool& positional_set, model::ParsedOptions& opts){
      i++;
      if(i < argv.size()){
        if(positional_set){
          return make_error(model::ErrorCode::INVALID_POSITIONAL,"","Multiple positional arguments not supported");
        }
        opts.target_path = std::string(argv[i]);
        positional_set = true;
      }
      return std::nullopt;
    }
    
    [[nodiscard]]std::optional<model::CliError> handle_long_option(std::string_view arg, ArgvView argv, size_t& i, model::ParsedOptions& opts){
      const auto eq = arg.find('=');
      const bool has_inline_value = (eq != std::string_view::npos);
      const std::string_view name = has_inline_value ? arg.substr(0, eq) : arg;
      const std::string_view inline_value = has_inline_value ? arg.substr(eq + 1) : std::string_view{};
      
      const auto* spec = find_spec(name);
      if(!spec){
        return make_error(model::ErrorCode::UNKNOWN_OPTION,name,"Unknown option");
      } 
      
      if(spec->value_type == spec::ValueType::NONE){
        if(has_inline_value){
          return make_error(model::ErrorCode::INVALID_VALUE,name,"Option does not accept a value", "", inline_value);
        }
        set_flag(opts,name);
        return std::nullopt;
      }
      
      std::string_view value;
      if(has_inline_value){
        value = inline_value;
      }
      else{
        ++i;
        if(i>= argv.size()){
          return make_error(model::ErrorCode::MISSING_VALUE,name,"Option requires a value");
        }
        value = argv[i];
      }
      if(auto err = validate_value(*spec,value); !err.message.empty()){
        return err;
      }
      return set_value(opts,*spec,value);
    }

    [[nodiscard]] std::optional<model::CliError> handle_short_option(std::string_view arg, ArgvView argv, size_t& i, model::ParsedOptions& opts){
      const auto* spec = find_spec(arg);
      if(!spec){
        return make_error(model::ErrorCode::UNKNOWN_OPTION,arg,"Unknown option");
      }
      if(spec->value_type == spec::ValueType::NONE){
        set_flag(opts,arg);
        return std::nullopt;
      }
      ++i;
      if(i>=argv.size()){
        return make_error(model::ErrorCode::MISSING_VALUE, arg, "Option requires a value");
      }
      const std::string_view value = argv[i];
      if (auto err = validate_value(*spec, value); !err.message.empty()) {
        return err;
      }
      return set_value(opts, *spec, value);
    }

  }

  [[nodiscard]] kls::cli::parser::ParseResult parse(kls::cli::parser::ArgvView argv) {
    model::ParsedOptions opts;
    bool positional_set = false;

    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string_view arg = argv[i];

        if (arg == "--") {
            if (auto err = handle_double_dash(argv, i, positional_set, opts); err) {
                return kls::Failure<model::CliError>{*err};
            }
            break;
        }
        
        if (arg.starts_with("--")) {
            if (auto err = handle_long_option(arg, argv, i, opts); err) {
                return kls::Failure<model::CliError>{*err};
            }
            continue;
        }
        
        if (arg.starts_with("-") && arg.size() > 1) {
            if (auto err = handle_short_option(arg, argv, i, opts); err) {
                return kls::Failure<model::CliError>{*err};
            }
            continue;
        }

        if (positional_set) {
            return kls::Failure<model::CliError>{
                make_error(model::ErrorCode::INVALID_POSITIONAL, arg, "Multiple positional arguments not supported")
            };
        }
        opts.target_path = std::string(arg);
        positional_set = true;
    }

    return kls::Success<model::ParsedOptions>{opts};
  }
}
