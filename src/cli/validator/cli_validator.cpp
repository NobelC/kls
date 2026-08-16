#include "kls/cli/validator/cli_validator.hpp"
#include "kls/cli/model/cli_error.hpp"
#include "kls/cli/model/parser_options.hpp"
#include "kls/cli/spec/cli_spec.hpp"
#include "kls/cli/spec/option_spec.hpp"
#include "kls/result.hpp"
#include <algorithm>
#include <string>
#include <string_view>

namespace kls::cli::validator {
  namespace {
    bool is_present(const model::ParsedOptions& opts, std::string_view name) {
      if (name == "--help" || name == "-H")       {return opts.help;}
      if (name == "--version" || name == "-V")    {return opts.version;}
      if (name == "--no-color")                   {return opts.no_color;}
      if (name == "--quiet" || name == "-q")      {return opts.quiet;}
      if (name == "--verbose")                    {return opts.verbose;}
      if (name == "--all" || name == "-a")        {return opts.all;}
      if (name == "--recursive" || name == "-r")  {return opts.recursive;}
      if (name == "--depth" || name == "-d")      {return opts.depth.has_value();}
      if (name == "--filter")                     {return opts.filter.has_value();}
      if (name == "--modified-before")            {return opts.modified_before.has_value();}
      if (name == "--modified-after")             {return opts.modified_after.has_value();}
      if (name == "--only-findings")              {return opts.only_findings;}
      if (name == "--min-severity")               {return opts.min_severity.has_value();}
      if (name == "--sort")                       {return opts.sort.has_value();}
      if (name == "--reverse")                    {return opts.reverse;}
      if (name == "--dirs-first")                 {return opts.dirs_first;}
      if (name == "--findings-first")             {return opts.findings_first;}
      if (name == "--long" || name == "-l")       {return opts.long_format;}
      if (name == "--no-header")                  {return opts.no_header;}
      return false;
    }

    model::CliError make_error(model::ErrorCode code, std::string_view option, std::string_view conflicting, std::string_view message){
      return model::CliError{
        .code = code,
        .option_name = std::string(option),
        .conflicting_with = std::string(conflicting),
        .expected_value = "",
        .actual_value = "",
        .message = std::string(message),
      };
    }
  }

  ValidationResult validate(const model::ParsedOptions& opts){
    for (const auto& spec: spec::CLI_SPECS){
      if(!is_present(opts,spec.name)) {continue;}

      // Conflicts
      auto conflict_it = std::ranges::find_if(spec.conflicts, [&opts](const auto& conflict){
        return is_present(opts, conflict);
      });
      if(conflict_it != spec.conflicts.end()){
        return kls::Failure<model::CliError>{
          make_error(model::ErrorCode::CONFLICTING_OPTIONS, spec.name, *conflict_it, "Options conflicts with another option")
        };
      }

      // Requirements
      auto requirement_it = std::ranges::find_if(spec.requirements, [&opts](const auto& req){
        return !is_present(opts, req);
      });
      if(requirement_it != spec.requirements.end()){
        return kls::Failure<model::CliError>{
          make_error(model::ErrorCode::MISSING_REQUIRED_OPTION, spec.name, *requirement_it, "Option requires another option")
        };
      }
    }
    return kls::Success<model::ParsedOptions>{opts};
  }
}
