#include <gtest/gtest.h>
#include "../include/core-hpp/tokenization.hpp"
#include "../include/core-hpp/parsing.hpp"
#include "../include/core-hpp/validator.hpp"
#include "../include/option/option-implementation.hpp"
#include "../include/core-hpp/executor.hpp"
#include <chrono>
#include <sys/resource.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

struct BenchmarkMetrics {
    double wall_time_ms;
    double user_time_ms;
    double system_time_ms;
    long max_rss_kb;
    long voluntary_context_switches;
    long involuntary_context_switches;
    long major_page_faults;
};

class SpeedSuite : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        CreatedOptionData();
    }

    BenchmarkMetrics run_benchmark(const std::vector<std::string>& input) {
        auto tokens = tokenization(input);
        auto parsed = parsing(tokens);
        if (!ValidationGroupToken(parsed)) {
            throw std::runtime_error("Validation failed for input");
        }

        struct rusage usage_start, usage_end;
        
        testing::internal::CaptureStdout();

        auto start = std::chrono::high_resolution_clock::now();
        getrusage(RUSAGE_SELF, &usage_start);

        executor(parsed);

        getrusage(RUSAGE_SELF, &usage_end);
        auto end = std::chrono::high_resolution_clock::now();

        testing::internal::GetCapturedStdout(); // Discard output

        auto wall_time = std::chrono::duration<double, std::milli>(end - start).count();
        
        long long user_start_us = static_cast<long long>(usage_start.ru_utime.tv_sec) * 1000000LL + usage_start.ru_utime.tv_usec;
        long long user_end_us   = static_cast<long long>(usage_end.ru_utime.tv_sec) * 1000000LL + usage_end.ru_utime.tv_usec;
        double user_time = static_cast<double>(user_end_us - user_start_us) / 1000.0;

        long long sys_start_us = static_cast<long long>(usage_start.ru_stime.tv_sec) * 1000000LL + usage_start.ru_stime.tv_usec;
        long long sys_end_us   = static_cast<long long>(usage_end.ru_stime.tv_sec) * 1000000LL + usage_end.ru_stime.tv_usec;
        double sys_time = static_cast<double>(sys_end_us - sys_start_us) / 1000.0;

        return {
            .wall_time_ms = wall_time,
            .user_time_ms = user_time,
            .system_time_ms = sys_time,
            .max_rss_kb = usage_end.ru_maxrss,
            .voluntary_context_switches = usage_end.ru_nvcsw - usage_start.ru_nvcsw,
            .involuntary_context_switches = usage_end.ru_nivcsw - usage_start.ru_nivcsw,
            .major_page_faults = usage_end.ru_majflt - usage_start.ru_majflt
        };
    }

    void print_metrics(const std::string& label, const BenchmarkMetrics& m) {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << " BENCHMARK: " << label << "\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << std::left << std::setw(30) << "Wall Time:" << std::fixed << std::setprecision(3) << m.wall_time_ms << " ms\n";
        std::cout << std::left << std::setw(30) << "User CPU Time:" << m.user_time_ms << " ms\n";
        std::cout << std::left << std::setw(30) << "System CPU Time:" << m.system_time_ms << " ms\n";
        std::cout << std::left << std::setw(30) << "Total CPU Time:" << (m.user_time_ms + m.system_time_ms) << " ms\n";
        std::cout << std::left << std::setw(30) << "Max RSS (Peak Memory):" << m.max_rss_kb << " KB\n";
        std::cout << std::left << std::setw(30) << "Voluntary Context Switches:" << m.voluntary_context_switches << "\n";
        std::cout << std::left << std::setw(30) << "Involuntary Context Switches:" << m.involuntary_context_switches << "\n";
        std::cout << std::left << std::setw(30) << "Major Page Faults (IO):" << m.major_page_faults << "\n";
        std::cout << std::string(50, '=') << "\n";
    }
};

TEST_F(SpeedSuite, SpeedTest_RecursiveList) {
    std::vector<std::string> input = {"--recursive", "."}; 
    
    std::cout << "[ INFO ] Starting benchmark for: kls --recursive\n";
    
    auto metrics = run_benchmark(input);
    print_metrics("kls --recursive ", metrics);
    
    SUCCEED();
}

TEST_F(SpeedSuite, SpeedTest_LargeList_LongFormat) {
    std::vector<std::string> input = {"--all", "."};
    
    std::cout << "[ INFO ] Starting benchmark for: kls --all \n";
    
    auto metrics = run_benchmark(input);
    print_metrics("kls --all", metrics);
    
    SUCCEED();
}
