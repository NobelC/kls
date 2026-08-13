#include "kls/cli/adapter/render_option_adapter.hpp"

namespace kls::cli::adapter {

report::RenderOptions to_render_options(const model::ParsedOptions& opts) {
    report::RenderOptions render_opts;

    render_opts.color = opts.no_color 
        ? report::ColorMode::never 
        : report::ColorMode::automatic;

    // Headers
    render_opts.show_headers = !opts.no_header;


    render_opts.show_findings = true;

    return render_opts;
}

} // namespace kls::cli::adapter
