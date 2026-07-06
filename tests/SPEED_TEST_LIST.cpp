#include <gtest/gtest.h>
#include "../include/kls/cli/parser/tokenization.hpp"
#include "../include/kls/cli/parser/parsing.hpp"
#include "../include/kls/cli/parser/validator.hpp"
#include "../include/kls/cli/option/option-implementation.hpp"
#include "../include/kls/cli/parser/executor.hpp"
#include <chrono>
#include <sys/resource.h>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>

// ---------------------------------------------------------------------------
// BenchmarkMetrics
// Stores per-run measurements. RSS is intentionally excluded because
// ru_maxrss is a process-wide peak and is meaningless after the first test.
// ---------------------------------------------------------------------------
struct BenchmarkMetrics {
    double wall_time_ms;
    double user_time_ms;
    double system_time_ms;
    long voluntary_context_switches;
    long involuntary_context_switches;
    long major_page_faults;
};

// ---------------------------------------------------------------------------
// BenchmarkStats
// Aggregated statistics across N repetitions.
// ---------------------------------------------------------------------------
struct BenchmarkStats {
    double wall_min_ms;
    double wall_max_ms;
    double wall_mean_ms;
    double wall_median_ms;
    double wall_stddev_ms;
    double cpu_mean_ms;
    int    repetitions;
};

// ---------------------------------------------------------------------------
// SpeedSuite
// ---------------------------------------------------------------------------
class SpeedSuite : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        CreatedOptionData();
    }

    // Run a single timed execution. Stdout is suppressed.
    // Throws if validation fails so the test fails clearly rather than
    // silently measuring nothing.
    BenchmarkMetrics run_once(const std::vector<std::string>& input) {
        auto tokens = tokenization(input);
        auto parsed = parsing(tokens);
        if (!ValidationGroupToken(parsed)) {
            throw std::runtime_error(
                "Validation failed — check that the options are registered correctly");
        }

        struct rusage usage_before{};
        struct rusage usage_after{};

        testing::internal::CaptureStdout();

        getrusage(RUSAGE_SELF, &usage_before);
        const auto wall_start = std::chrono::high_resolution_clock::now();

        executor(parsed);

        const auto wall_end = std::chrono::high_resolution_clock::now();
        getrusage(RUSAGE_SELF, &usage_after);

        testing::internal::GetCapturedStdout();

        const double wall_ms =
            std::chrono::duration<double, std::milli>(wall_end - wall_start).count();

        auto to_us = [](const timeval& tv) -> long long {
            return static_cast<long long>(tv.tv_sec) * 1'000'000LL + tv.tv_usec;
        };

        const double user_ms =
            static_cast<double>(to_us(usage_after.ru_utime) - to_us(usage_before.ru_utime))
            / 1000.0;

        const double sys_ms =
            static_cast<double>(to_us(usage_after.ru_stime) - to_us(usage_before.ru_stime))
            / 1000.0;

        return {
            .wall_time_ms               = wall_ms,
            .user_time_ms               = user_ms,
            .system_time_ms             = sys_ms,
            .voluntary_context_switches   = usage_after.ru_nvcsw  - usage_before.ru_nvcsw,
            .involuntary_context_switches = usage_after.ru_nivcsw - usage_before.ru_nivcsw,
            .major_page_faults            = usage_after.ru_majflt - usage_before.ru_majflt,
        };
    }

    // Run N repetitions and compute statistics.
    // The first repetition is treated as a warm-up and excluded from stats
    // because it includes page-cache cold-start effects that do not reflect
    // steady-state performance.
    BenchmarkStats run_n(const std::vector<std::string>& input,int repetitions = 5) {
        std::vector<double> wall_times;
        wall_times.reserve(static_cast<size_t>(repetitions));

        double cpu_sum = 0.0;

        // Warm-up run — results discarded
        run_once(input);

        for (int i = 0; i < repetitions; ++i) {
            const auto m = run_once(input);
            wall_times.push_back(m.wall_time_ms);
            cpu_sum += m.user_time_ms + m.system_time_ms;
        }

        // Mean
        const double mean =
            std::accumulate(wall_times.begin(), wall_times.end(), 0.0)
            / static_cast<double>(repetitions);

        // Stddev
        double variance = 0.0;
        for (const double t : wall_times) {
            const double diff = t - mean;
            variance += diff * diff;
        }
        variance /= static_cast<double>(repetitions);
        const double stddev = std::sqrt(variance);

        // Median
        std::vector<double> sorted = wall_times;
        std::ranges::sort(sorted);
        const double median = (repetitions % 2 == 0)
            ? (sorted[static_cast<size_t>(repetitions) / 2 - 1] + sorted[static_cast<size_t>(repetitions) / 2]) / 2.0
            : sorted[static_cast<size_t>(repetitions) / 2];

        return {
            .wall_min_ms    = sorted.front(),
            .wall_max_ms    = sorted.back(),
            .wall_mean_ms   = mean,
            .wall_median_ms = median,
            .wall_stddev_ms = stddev,
            .cpu_mean_ms    = cpu_sum / static_cast<double>(repetitions),
            .repetitions    = repetitions,
        };
    }

    void print_stats(const std::string& label, const BenchmarkStats& s) {
        const std::string sep(58, '=');
        const std::string div(58, '-');
        constexpr int W = 32;

        std::cout << "\n" << sep << "\n";
        std::cout << " BENCHMARK: " << label << "\n";
        std::cout << " Repetitions: " << s.repetitions
                  << "  (+ 1 warm-up, excluded)\n";
        std::cout << div << "\n";
        std::cout << std::left  << std::fixed << std::setprecision(3);
        std::cout << std::setw(W) << "Wall time — min:"    << s.wall_min_ms    << " ms\n";
        std::cout << std::setw(W) << "Wall time — max:"    << s.wall_max_ms    << " ms\n";
        std::cout << std::setw(W) << "Wall time — mean:"   << s.wall_mean_ms   << " ms\n";
        std::cout << std::setw(W) << "Wall time — median:" << s.wall_median_ms << " ms\n";
        std::cout << std::setw(W) << "Wall time — stddev:" << s.wall_stddev_ms << " ms\n";
        std::cout << std::setw(W) << "CPU time  — mean:"   << s.cpu_mean_ms    << " ms\n";
        std::cout << sep << "\n";
    }
};

// ---------------------------------------------------------------------------
// Tests
// Each test documents exactly what options are passed and why that
// combination is being measured.
// ---------------------------------------------------------------------------

// Baseline: project directory without hidden files.
// Expected to complete well under 500 ms on any modern machine.
TEST_F(SpeedSuite, Baseline_ProjectDir_Recursive) {
    const std::vector<std::string> input = {"--recursive", "."};
    std::cout << "[ INFO ] kls --recursive .\n";
    print_stats("kls --recursive .", run_n(input));
    SUCCEED();
}

// Full home traversal — health checks active.
// This is the worst-case workload for health check overhead.
TEST_F(SpeedSuite, Stress_HomeDir_WithHealth) {
    const std::vector<std::string> input = {"--all", "--recursive", "/home/nobel/"};
    std::cout << "[ INFO ] kls --all --recursive /home/nobel/\n";
    print_stats("kls --all --recursive /home/nobel/ (health ON)", run_n(input, 3));
    SUCCEED();
}

// Same traversal with health disabled.
// Diff between this and the test above isolates PerformHealthChecks cost.
TEST_F(SpeedSuite, Stress_HomeDir_NoHealth) {
    const std::vector<std::string> input = {"--all", "--recursive", "--no-health", "/home/nobel/"};
    std::cout << "[ INFO ] kls --all --recursive --no-health /home/nobel/\n";
    print_stats("kls --all --recursive /home/nobel/ (health OFF)", run_n(input, 3));
    SUCCEED();
}

// Shallow listing of /tmp — fast sanity check.
// If this exceeds ~50 ms something is fundamentally broken.
TEST_F(SpeedSuite, Sanity_Tmp_Shallow) {
    const std::vector<std::string> input = {"--all", "/tmp"};
    std::cout << "[ INFO ] kls --all /tmp\n";
    print_stats("kls --all /tmp (shallow)", run_n(input));
    SUCCEED();
}
