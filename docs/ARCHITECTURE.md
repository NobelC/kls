# Architecture

## Status

This document describes the target architecture for `stabilize/core-baseline`.
It is a design contract, not a claim that every component is already
implemented.

## System objective

`kls` audits one Linux directory tree and produces:

- Filesystem object metadata.
- Security findings with structured evidence.
- Coverage diagnostics.
- Human-readable or machine-readable reports.
- A deterministic exit status.

The architecture prioritizes:

1. Correctness.
2. Explicit uncertainty.
3. Stable failure semantics.
4. Security against hostile directory trees.
5. Measurable performance.

## High-level pipeline

```text
CLI
 |
 v
Audit configuration
 |
 v
Root directory acquisition
 |
 v
Descriptor-relative scanner
 |
 +--> Coverage diagnostics
 |
 v
Audit entries
 |
 v
Independent analyzers
 |
 v
Unified findings
 |
 v
Filters and policy evaluation
 |
 v
Table / JSON / CSV / SARIF renderer
 |
 v
Exit-status evaluation
```

## Components

### CLI

Responsibilities:

- Parse one directory target.
- Parse typed options.
- Validate conflicts and requirements.
- Produce an immutable `AuditConfig`.
- Return usage errors without exceptions.

The CLI specification must be the single source of truth for:

- Parser registration.
- Validation.
- `--help`.
- Manual page.
- Shell completions.
- Public documentation.

Numeric parsing should use `std::from_chars`. The parser must reject trailing
characters, negative values where prohibited, and out-of-range values.

### Audit coordinator

The coordinator owns one audit run.

Responsibilities:

- Acquire the root directory.
- Detect available kernel features.
- Select the compatibility mode.
- Start and stop scanner workers.
- Aggregate entries, findings, and coverage.
- Apply output filters and failure thresholds.
- Return an explicit result.

Conceptual result type:

```cpp
struct AuditResult {
    AuditSummary summary;
    std::vector<AuditEntry> entries;
    CoverageReport coverage;
    std::vector<Diagnostic> diagnostics;
};
```

Core code should return explicit result types, preferably `std::expected`, and
must not use exceptions for ordinary operational errors.

### Descriptor-relative scanner

The scanner should acquire the root once and perform subsequent operations
relative to directory file descriptors.

Conceptual work item:

```cpp
struct DirectoryJob {
    UniqueFd directory;
    RelativePath display_path;
    std::uint32_t depth;
};
```

Metadata requests should use a directory descriptor and entry name:

```text
statx(directory_fd, entry_name, flags, mask, &metadata)
```

Absolute paths are presentation data, not object handles.

The scanner should:

- Use no-follow behavior by default.
- Detect directory cycles.
- Cross mount points.
- Exclude configured pseudo-filesystems.
- Bound open descriptors.
- Bound pending work.
- Record every skipped or incomplete object.
- Support cancellation.

### Object identity

A pathname is not a stable identity.

Conceptual identity:

```cpp
struct ObjectIdentity {
    std::uint64_t device_major;
    std::uint64_t device_minor;
    std::uint64_t inode;
    std::optional<std::uint64_t> mount_id;
};
```

When an analyzer requires a second operation:

1. Capture initial identity.
2. Open or inspect the object relative to its parent directory.
3. Capture identity again.
4. Compare identities.
5. Mark the object unstable if identity changed.
6. Never combine evidence from different objects into one finding.

`mount_id` availability depends on kernel and filesystem support.

### Compatibility modes

#### Compatible mode

Target: Linux `4.11` to `5.5`.

Expected mechanisms:

- `statx`.
- `openat`.
- `fstatat`.
- `O_NOFOLLOW`.
- Identity verification before and after multi-step analysis.

This mode cannot provide the same pathname-resolution restrictions as
`openat2`.

#### Full mode

Target: Linux `5.6+`.

Adds `openat2` and resolution policies where available, including:

- Resolution beneath the audit root.
- Magic-link restrictions.
- Explicit mount-crossing policy.
- Stronger symlink handling.

The active mode and unavailable features must be included in the audit report.

### Audit entry

Conceptual entry:

```cpp
struct AuditEntry {
    ObjectIdentity identity;
    RelativePath path;
    FileType type;
    Metadata metadata;
    StabilityState stability;
    std::vector<Finding> findings;
};
```

Derived booleans should be avoided when they can be obtained from metadata or
findings.

### Findings

All observations use one model.

```cpp
enum class FindingCategory {
    suid,
    sgid,
    capabilities,
    symlink,
    timestamp,
    filesystem,
    ownership,
    coverage
};

enum class Severity {
    info,
    low,
    medium,
    high,
    critical
};

struct Finding {
    FindingId id;
    FindingCategory category;
    Severity severity;
    MessageId message;
    Evidence evidence;
};
```

Requirements:

- IDs are unique.
- Existing IDs remain stable when semantics remain stable.
- Evidence is structured.
- An informational finding is allowed.
- Renderers do not implement security rules.
- Filters operate on findings without knowing analyzer internals.
- Machine output preserves category, severity, ID, message, and evidence.

### Analyzers

Initial analyzer boundaries:

- `PermissionAnalyzer`
- `OwnershipAnalyzer`
- `CapabilityAnalyzer`
- `SymlinkAnalyzer`
- `TimestampAnalyzer`
- `FilesystemFlagAnalyzer`
- `DeviceNodeAnalyzer`
- `IntegrityAnalyzer`

Analyzers:

- Receive an audit context.
- Return zero or more findings.
- Do not print.
- Do not parse CLI options.
- Do not sort or filter.
- Avoid reopening an object when a shared descriptor is sufficient.
- Declare required metadata or descriptor access.
- Remain independently testable.

Conceptual context:

```cpp
struct AuditContext {
    const AuditConfig& config;
    const ObjectIdentity& identity;
    const Metadata& metadata;
    BorrowedFd parent_directory;
    std::optional<BorrowedFd> object;
    std::string_view name;
};
```

### Coverage

Coverage is a first-class result.

Minimum counters:

- Directories visited.
- Objects discovered.
- Objects inspected.
- Objects skipped.
- Permission denied.
- Objects vanished.
- Objects changed identity.
- Unsupported attributes.
- Pseudo-filesystems excluded.
- Resource-limit failures.
- I/O failures.

Minimum diagnostic classes:

```text
permission_denied
vanished
unsupported_filesystem
attribute_unavailable
unstable_object
io_error
symlink_escape
mount_boundary
pseudo_filesystem_excluded
resource_limit
internal_error
```

An audit with coverage failures is not equivalent to a clean audit.

### Symlinks

Default behavior:

- Inspect the link itself.
- Do not follow its target.
- Record its textual target.
- Detect broken targets.
- Detect loops.
- Detect escapes from the audit root.

Future explicit controls may include:

```text
--follow-symlinks
--allow-outside-root
```

Following links must maintain a visited set based on object identity.

### Pseudo-filesystems

Dynamic pseudo-filesystems are excluded by default:

- `/proc`
- `/sys`
- `/dev`
- `/run`

Exclusion must:

- Produce a warning or coverage diagnostic.
- Affect coverage counters.
- Appear in structured output.
- Be configurable in a future policy layer.

### Policy and configuration

Future policy files may configure:

- Severity overrides.
- Disabled rules.
- Allowed paths.
- Excluded paths.
- Category selection.
- Finding thresholds.

A known path is context, not proof of safety. Whitelisted system locations must
still be inspected. A path can reduce or add contextual severity only through
an explicit, documented rule.

### Rendering

Renderers receive an immutable result model.

Required renderers:

- Table.
- JSON.
- CSV.
- SARIF.

Structured renderers must:

- Escape untrusted strings.
- Avoid ANSI sequences.
- Include schema or format version.
- Include `kls` version.
- Include active compatibility mode.
- Include target and timestamps.
- Include coverage.
- Include diagnostics.
- Include findings and evidence.

### Exit-status evaluation

Exit status is evaluated after the audit result exists:

```text
0  Audit completed.
2  Invalid CLI.
3  Incomplete audit.
4  Internal failure.
5  Configured finding threshold exceeded.
```

Finding thresholds do not alter the finding data; they only influence policy
evaluation and process status.

### Concurrency

Target structure:

```text
Directory traversal
        |
        v
Bounded work queue
        |
        +-- Worker 1
        +-- Worker 2
        +-- Worker N
                 |
                 v
          Worker-local buffers
                 |
                 v
             Final merge
```

Requirements:

- Worker count defaults from CPU availability.
- Work queues are bounded.
- Backpressure prevents unbounded memory growth.
- Workers use local result buffers.
- Shared vectors do not receive unsynchronized writes.
- Cancellation uses `std::jthread` and `std::stop_token` where practical.
- File descriptor usage is bounded separately from thread count.
- Failure in one worker is propagated to the coordinator.
- Ordering is applied after collection unless a streaming renderer is valid.

### Performance

Correctness and coverage semantics precede optimization.

Future benchmarks must report:

- Hardware.
- Kernel.
- Filesystem.
- Compiler.
- Build type.
- Dataset.
- Enabled analyzers.
- Thread count.
- Time.
- Peak memory.
- Coverage result.

Potential optimization areas:

- Avoid duplicated full paths.
- Avoid fixed large reserves per entry.
- Represent extensions as views or offsets.
- Make symlink targets optional.
- Resolve UID/GID once per unique identifier.
- Share descriptors among analyzers.
- Stream results when global ordering is not requested.
- Evaluate polymorphic allocators only after measurement.

## Dependency policy

Prefer:

- Linux system calls.
- libc.
- The C++ standard library.
- Small, pinned test-only dependencies.

Every runtime dependency requires justification based on security,
maintainability, portability within Linux, and measurable value.

## Source layout target

```text
include/kls/
  audit/
  scanner/
  analyzers/
  report/
  cli/

src/
  audit/
  scanner/
  analyzers/
  report/
  cli/

tests/
  cli/
  scanner/
  analyzers/
  report/
  integration/
```
