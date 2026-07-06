# kls

[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)](#project-status)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-black)](#platform-support)
[![Language: C++20](https://img.shields.io/badge/C%2B%2B-20-blue)](#build-from-source)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue)](LICENSE)

> **What's in here, and should I be worried?**

`kls` is an experimental, read-only Linux filesystem security auditor. It
inspects a directory tree, identifies security-relevant conditions, and
reports both its findings and the coverage limitations of the audit.

`kls` is not an `ls` replacement. Its primary users are security analysts,
with additional use cases for system administrators, DevSecOps engineers,
developers, students, and advanced Linux users.

## Project status

`kls` is **experimental**.

The project is currently establishing its `0.2.0` core baseline. CLI options,
finding schemas, identifiers, output formats, and internal APIs may change
before `1.0.0`.

The documentation deliberately separates:

- **Current experimental scope**: checks already represented in the codebase,
  including partial implementations that are being stabilized.
- **Baseline commitments**: behavior that `stabilize/core-baseline` must make
  consistent and testable.
- **Planned capabilities**: features that are not yet public guarantees.

Do not treat an absence of findings as proof that a system is secure.

## Design principles

- **Read-only and report-only**: `kls` does not intentionally modify file
  contents, permissions, ownership, extended attributes, or directory
  entries.
- **Evidence over assertions**: findings should include the metadata or
  conditions that produced them.
- **Coverage is part of the result**: inaccessible, vanished, unsupported, or
  unstable objects must be reported instead of silently ignored.
- **Linux-native security**: Linux APIs are used directly when they provide
  stronger metadata or pathname-resolution guarantees.
- **Reliability before feature count**: new detectors should not be added
  until the scanner, finding model, CLI, tests, and exit semantics are stable.
- **Performance with measurement**: speed and efficient resource usage are
  explicit goals, but public performance claims require reproducible
  benchmarks.

## Audit scope

The intended command model is:

```text
kls [DIRECTORY] [OPTIONS]
```

A run accepts one directory and recursively audits the objects below it.

Baseline traversal semantics:

- Cross mount points during recursive traversal.
- Inspect symbolic links without following their targets by default.
- Detect broken symbolic links.
- Prevent symlink resolution from silently escaping the audit root.
- Exclude dynamic pseudo-filesystems such as `/proc`, `/sys`, `/dev`, and
  `/run` by default and report the exclusion.
- Support both unprivileged and privileged execution.
- Report reduced coverage when permissions prevent inspection.

Running as root may improve coverage, but root is not required.

## Current experimental detection scope

The codebase currently contains checks or partial implementations for:

- SUID and SGID conditions.
- World-writable permissions.
- Linux file capabilities.
- Immutable and append-only attributes.
- Unknown or unmapped UID/GID ownership.
- Broken symbolic links.
- Future timestamps and temporal anomalies.
- Recursive traversal.
- Filtering and sorting.

These checks are under stabilization. Their presence in this section does not
yet imply a stable detector contract, complete coverage, or final severity.

Executable-format classification is not part of the current scope.

## Finding model

All security observations are represented as findings rather than separate
health and capability systems.

Severity levels:

```text
info
low
medium
high
critical
```

A finding may be informational. The existence of a finding does not
necessarily imply exploitation or compromise.

Finding families retain compact prefixes:

| Prefix | Category |
| --- | --- |
| `SU` | SUID |
| `SG` | SGID |
| `CA` | Linux capabilities |
| `SY` | Symbolic links |
| `TS` | Timestamps |
| `FS` | Filesystem |
| `OW` | Ownership |
| `CV` | Audit coverage |

Existing finding IDs should be preserved whenever their meaning remains
unchanged. New IDs must be documented and unique.

## Output

The default output is audit-oriented rather than inventory-oriented. It should
prioritize:

1. Audit coverage.
2. Counts by severity.
3. Objects with findings.
4. Compact finding identifiers.

Planned baseline formats:

- Human-readable table.
- JSON.
- CSV.
- SARIF.

Planned audit controls:

```text
--inventory
--details
--summary
--min-severity=<info|low|medium|high|critical>
--category=<category>
--fail-on=<low|medium|high|critical>
--fail-on-findings=<count>
--format=<table|json|csv|sarif>
```

Color output must be enabled only when standard output is a terminal. Structured
formats must never contain ANSI escape sequences.

`kls` will not produce a single global risk score. Counts, categories,
severity, evidence, and coverage are more defensible than a synthetic score.

## Exit status contract

The target exit-code contract is:

| Code | Meaning |
| ---: | --- |
| `0` | Audit completed. Findings may exist. |
| `2` | Invalid command-line usage. |
| `3` | Audit incomplete because of filesystem or coverage errors. |
| `4` | Internal failure. |
| `5` | A configured finding threshold was exceeded. |

Findings do not cause failure by default. Exit code `5` is reserved for
explicit policies such as `--fail-on` and `--fail-on-findings`.

## Security guarantees and limitations

`kls` performs a best-effort audit of a potentially changing filesystem.

The baseline architecture is intended to:

- Use directory-relative file operations.
- Avoid repeated absolute pathname resolution.
- Verify object identity when inspection requires multiple operations.
- Report objects that disappear, change identity, or cannot be inspected
  consistently.
- Report incomplete coverage.

A live filesystem is not an atomic snapshot. Other processes may modify files
while the audit is running, and even one metadata request may observe fields
from different moments. For higher-confidence point-in-time auditing, use a
read-only filesystem snapshot when the storage platform supports one.

`kls` does not intentionally modify the audited tree. Reads can still have
external or filesystem-dependent effects, including access-time updates,
automount activation, remote filesystem traffic, or behavior generated by
dynamic pseudo-filesystems. The implementation should minimize these effects,
but cannot promise that every read is externally invisible.

## Non-goals

`kls` is not a replacement for:

- Antivirus or antimalware software.
- Endpoint detection and response systems.
- Runtime integrity monitoring.
- Package or dependency vulnerability scanners.
- SELinux or AppArmor policy auditing.
- Incident response.
- Manual security review.

## Platform support

`kls` is Linux-only.

The compatibility strategy is capability-based:

| Mode | Kernel | Intended behavior |
| --- | --- | --- |
| Compatible | Linux `4.11` to `5.5` | `statx`, directory-relative operations, no-follow behavior, and identity verification where possible. |
| Full | Linux `5.6+` | Adds `openat2` resolution restrictions for stronger containment and symlink handling. |

Support depends on both the kernel and the backing filesystem. A filesystem may
omit requested `statx` fields, reject extended attributes, or expose different
semantics. `kls` must detect these conditions and reflect them in audit
coverage.

The currently tested filesystem is **ext4**. Other filesystems are best effort
until they are added to the test matrix.

Containers, WSL, chroot environments, network filesystems, overlay filesystems,
and other filesystems are not officially supported yet.

## Installation

### GitHub Releases

Prebuilt release artifacts are the intended binary distribution method.

Initial architecture targets:

- `x86_64`
- `AArch64`

Artifacts should be published only after their architecture is covered by CI.
Until release artifacts are available, build from source.

### Build from source

Requirements:

- Linux.
- CMake `3.15+`.
- A C++20 compiler.
- A kernel compatible with the selected audit mode.
- `gzip` optionally, for compressed manual pages.

Production build:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_SANITIZERS=OFF \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build build --parallel
sudo cmake --install build
```

Developer build:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_SANITIZERS=ON \
  -DBUILD_TESTING=ON

cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The test command above is part of the baseline contract. Until the CMake test
integration is enabled, it describes the target developer workflow rather than
a guarantee of the current default branch.

### Uninstall

```bash
sudo cmake --build build --target uninstall
```

## Architecture

The target architecture separates:

1. CLI parsing and validation.
2. Descriptor-relative filesystem scanning.
3. Independent analyzers.
4. A unified finding model.
5. Coverage and diagnostics.
6. Human and structured renderers.

See [Architecture](docs/ARCHITECTURE.md) for the design and
[Threat Model](docs/THREAT-MODEL.md) for security assumptions and residual
risks.

The implementation checklist for the stabilization branch is maintained in
[Core Baseline](docs/BASELINE.md).

## Performance

Performance, predictable memory use, and scalable traversal are project goals.

No numeric performance or memory claims are made yet. Benchmarks will be
published only when they are reproducible and include:

- CPU and memory.
- Kernel version.
- Filesystem.
- Dataset shape and object count.
- Build configuration.
- Enabled analyzers.
- Thread count.
- Peak memory and elapsed time.

## Contributing

External contributions are welcome.

Before submitting a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md).
Large architectural changes should be discussed before implementation.

## Security reports

General defects belong in GitHub Issues.

Potential vulnerabilities in `kls` itself should be reported privately through
GitHub Private Vulnerability Reporting or a repository security advisory. See
[SECURITY.md](SECURITY.md).

## Versioning

`kls` follows Semantic Versioning:

- `0.x.y`: experimental; CLI and schemas may change.
- `1.0.0`: first stable public contract.

Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

`kls` is licensed under **GPL-3.0-only**.
