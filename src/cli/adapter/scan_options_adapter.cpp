#include "kls/cli/adapter/scan_option_adapter.hpp"
#include <cstddef>
#include <limits>

namespace kls::cli::adapter {
  [[nodiscard]] scanner::ScanOptions to_scan_options(const model::ParsedOptions& opts){
    scanner::ScanOptions scan_opts;
  
    scan_opts.recursive = opts.recursive;
    scan_opts.include_hidden = opts.all;

    if(opts.depth.has_value()){
      scan_opts.maximum_depth = static_cast<std::size_t>(*opts.depth);
    }
    else{
      scan_opts.maximum_depth = std::numeric_limits<std::size_t>::max();
    }
    scan_opts.analyze_capabilities = true;
    scan_opts.analyze_health = true;
    //scan_opts.symlink_status = ;
    return scan_opts;
  }
}
