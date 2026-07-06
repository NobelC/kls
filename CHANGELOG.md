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

### Removed

- macOS and generic POSIX support claims.
- AUR installation claims.
- DEB and RPM support claims.
- Global risk-score plans.
- Executable-format classification from the current detector scope.

## [0.2.0] - Unreleased

`0.2.0` is the planned core-baseline release. It will establish coherent CLI,
finding, coverage, security, test, and compatibility contracts.

## [0.1.1]

Historical experimental release preceding the core-baseline stabilization.
