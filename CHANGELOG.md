# Changelog

All notable changes to `kls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Formal Linux-only project scope.
- Experimental project-status declaration.
- Security policy and private vulnerability reporting guidance.
- Contribution and coding conventions.
- Target architecture for descriptor-relative auditing.
- Threat model for hostile and concurrently changing filesystems.
- Core-baseline implementation checklist.
- Target table, JSON, CSV, and SARIF output formats.
- Target audit coverage and exit-code contracts.
- Declarative CLI architecture with spec-based parser and validator
- Output processor with filtering, sorting, and grouping capabilities
- Constexpr finding registry with 12 capability findings and 33 health findings
- Constexpr whitelist for 13 standard system paths
- Comprehensive unit tests for output processor
- Modern ID class with constexpr support and default constructor

### Changed

- Reframed `kls` from a directory-listing replacement into a filesystem
  security auditor.
- Defined findings as the unified representation for permissions,
  capabilities, ownership, symlink, timestamp, filesystem, integrity, and
  coverage observations.
- Defined performance as a measured goal rather than an unsupported public
  claim.
- Defined GitHub Releases and source builds as the intended distribution
  channels.
- Defined GPL-3.0-only as the project license identifier.
- Restructured ScanOutput to use AuditItem for better encapsulation
- Migrated from mutable global registries to constexpr finding system
- Normalized all include paths to use target_include_directories
- Replaced legacy CLI parser/validator/executor with declarative architecture
- Modernized ID class for aggregate initialization compatibility
- Added default member initializers to aggregate structs (ScanError, ScanIssue,
  CandidateEntry, Finding, OptionSpec, AliasIndex, CliError, DirectoryRecord)

### Fixed

- Critical segfault in validator caused by inverted requirements logic and
  missing bounds check
- Owner/group names always showing "UNKNOWN" due to incorrect assignments
- Cppcheck warnings: passedByValue, useStlAlgorithm, knownConditionTrueFalse,
  unusedFunction, comparisonOfBoolWithBoolError
- Redundant condition in capability_analyzer
- Unused variable assignment in cli_parser
- Raw loop replaced with std::ranges::all_of in cli_parser
- Collect_metadata signature changed to const reference for performance

### Removed

- macOS and generic POSIX support claims.
- AUR installation claims.
- DEB and RPM support claims.
- Global risk-score plans.
- Executable-format classification from the current detector scope.
- Legacy CAPABILITIES-register directory (4 files)
- Legacy SUID-SGID-register directory (4 files)
- Legacy white-list-routes directory (2 files)
- Legacy CLI command/token/option/error directories
- Obsolete CMake-generated Makefile from tests
- Legacy test files (TOKENIZATION_TEST, PARSING_TEST, VALIDATION_TEST,
  EXECUTOR_TEST, SPEED_TEST_LIST)

## [0.2.0] - Unreleased

`0.2.0` is the planned core-baseline release. It will establish coherent CLI,
finding, coverage, security, test, and compatibility contracts.

## [0.1.1]

Historical experimental release preceding the core-baseline stabilization.
