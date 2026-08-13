#include "kls/cli/adapter/output_processor.hpp"
#include "kls/cli/model/parser_options.hpp"
#include "kls/scanner/scanner.hpp"
#include "kls/filesystem/file_type.hpp"
#include <gtest/gtest.h>

namespace {

kls::scanner::AuditItem make_item(const std::string& name, std::size_t size) {
    kls::scanner::AuditItem item;
    item.entry.name = name;
    item.entry.size = size;
    item.entry.type = kls::filesystem::FileType::regular;
    item.entry.mode = 0644;
    item.entry.uid = 1000;
    item.entry.gid = 1000;
    item.entry.mtime = 0;
    item.entry.nlinks = 1;
    item.entry.full_path = "./" + name;
    item.entry.extension = "";
    return item;
}

} // namespace

TEST(OutputProcessorTest, SortBySizeDescending) {
   
    kls::scanner::ScanOutput output;
    output.items.push_back(make_item("small.txt", 100));
    output.items.push_back(make_item("large.txt", 5000));
    output.items.push_back(make_item("medium.txt", 1000));
    
    kls::cli::model::ParsedOptions opts;
    opts.sort = "size";
    
    // Act
    kls::cli::adapter::process_output(output, opts);
    

    ASSERT_EQ(output.items.size(), 3);
    EXPECT_EQ(output.items[0].entry.name, "large.txt");
    EXPECT_EQ(output.items[0].entry.size, 5000);
    EXPECT_EQ(output.items[1].entry.name, "medium.txt");
    EXPECT_EQ(output.items[1].entry.size, 1000);
    EXPECT_EQ(output.items[2].entry.name, "small.txt");
    EXPECT_EQ(output.items[2].entry.size, 100);
}

TEST(OutputProcessorTest, SortByNameAscending) {
    kls::scanner::ScanOutput output;
    output.items.push_back(make_item("zebra.txt", 100));
    output.items.push_back(make_item("apple.txt", 100));
    output.items.push_back(make_item("mango.txt", 100));
    
    kls::cli::model::ParsedOptions opts;
    opts.sort = "name";
    
    kls::cli::adapter::process_output(output, opts);
    
    ASSERT_EQ(output.items.size(), 3);
    EXPECT_EQ(output.items[0].entry.name, "apple.txt");
    EXPECT_EQ(output.items[1].entry.name, "mango.txt");
    EXPECT_EQ(output.items[2].entry.name, "zebra.txt");
}

TEST(OutputProcessorTest, FilterByPattern) {
    kls::scanner::ScanOutput output;
    output.items.push_back(make_item("file.cpp", 100));
    output.items.push_back(make_item("file.hpp", 100));
    output.items.push_back(make_item("file.txt", 100));
    
    kls::cli::model::ParsedOptions opts;
    opts.filter = "*.cpp";
    
    kls::cli::adapter::process_output(output, opts);
    
    ASSERT_EQ(output.items.size(), 1);
    EXPECT_EQ(output.items[0].entry.name, "file.cpp");
}

TEST(OutputProcessorTest, DirsFirst) {
    kls::scanner::ScanOutput output;
    
    kls::scanner::AuditItem file_item = make_item("file.txt", 100);
    file_item.entry.type = kls::filesystem::FileType::regular;
    
    kls::scanner::AuditItem dir_item = make_item("dir", 0);
    dir_item.entry.type = kls::filesystem::FileType::directory;
    
    output.items.push_back(file_item);
    output.items.push_back(dir_item);
    
    kls::cli::model::ParsedOptions opts;
    opts.dirs_first = true;
    
    kls::cli::adapter::process_output(output, opts);
    
    ASSERT_EQ(output.items.size(), 2);
    EXPECT_EQ(output.items[0].entry.type, kls::filesystem::FileType::directory);
    EXPECT_EQ(output.items[1].entry.type, kls::filesystem::FileType::regular);
}
