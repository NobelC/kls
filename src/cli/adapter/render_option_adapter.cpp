#include "kls/cli/adapter/render_option_adapter.hpp"

namespace kls::cli::adapter {

// ARCHITECTURAL NOTE: Anti-Corruption Layer.
// Translates CLI-specific flags into domain-agnostic rendering instructions.
// This prevents the core renderer from depending on CLI parsing models.
report::RenderOptions to_render_options(const model::ParsedOptions& opts) {
    report::RenderOptions render_opts;

    // Color policy: CLI can explicitly disable colors. 
    // Otherwise, the renderer defaults to TTY-aware automatic detection.
    if (opts.no_color) {
        render_opts.color = report::ColorMode::never;
    } else {
        render_opts.color = report::ColorMode::automatic;
    }

    // Header visibility is directly inverted from the CLI flag.
    if (opts.no_header) {
        render_opts.show_headers = false;
    } else {
        render_opts.show_headers = true;
    }

    // Findings are always rendered in the current baseline.
    // Filtering out findings is handled upstream by `process_output`, not the renderer.
    render_opts.show_findings = true;

    return render_opts;
}

} // namespace kls::cli::adapter
