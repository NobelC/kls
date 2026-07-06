# Contributing to kls

`kls` welcomes external contributions. The project is experimental, but
changes must preserve its security-oriented design.

## Before contributing

For bug fixes and small improvements, open a focused pull request.

Before implementing a large feature or architectural change, open a discussion
or issue describing:

- The problem.
- The proposed behavior.
- Security implications.
- Compatibility implications.
- Expected tests.
- Performance or resource implications.

During `stabilize/core-baseline`, reliability work takes priority over new
detectors.

## Development principles

Contributions should preserve these constraints:

- Linux-only.
- Read-only and report-only.
- No intentional filesystem mutation.
- Explicit error propagation.
- Coverage failures must not be hidden.
- Evidence must remain separate from interpretation.
- Minimal dependencies.
- No exception-based control flow in the core.
- Prefer `std::expected` or explicit result types.
- Avoid `std::any`.
- Avoid mutable global registries.
- Avoid unnecessary global functions.
- Do not add performance claims without reproducible measurements.

## Language and naming

All code, comments, commit messages, and project documentation must be in
English.

C++ naming conventions:

| Element | Convention | Example |
| --- | --- | --- |
| Types | `PascalCase` | `AuditResult` |
| Functions | `snake_case` | `run_audit` |
| Variables | `snake_case` | `root_directory` |
| Namespaces | `snake_case` | `kls::scanner` |
| Files | `snake_case` | `audit_result.hpp` |
| `constexpr` variables | `kPascalCase` | `kDefaultQueueCapacity` |
| Enum values | `snake_case` | `Severity::critical` |
| Macros | `UPPER_SNAKE_CASE` | `KLS_HAS_OPENAT2` |

Use `clang-format` for C++ formatting.

## Commit convention

Use Conventional Commits.

Examples:

```text
fix(scanner): preserve object identity across analysis
feat(report): add sarif renderer
test(capabilities): cover malformed capability xattrs
docs(security): document live filesystem limitations
refactor(model): replace health flags with findings
perf(scanner): reduce path allocation in traversal
```

Keep commits focused. Do not mix unrelated refactors, formatting, and behavior
changes.

## Branches

Use descriptive branch names grouped by purpose:

```text
fix/<description>
feat/<description>
docs/<description>
refactor/<description>
test/<description>
stabilize/<description>
```

The current stabilization branch is:

```text
stabilize/core-baseline
```

## Build

Developer configuration:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_SANITIZERS=ON \
  -DBUILD_TESTING=ON

cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The baseline must support GCC and Clang.

## Tests

Every behavioral change should include tests.

Important test areas:

- CLI parsing and validation.
- Numeric overflow and malformed values.
- Exit codes.
- Recursive traversal.
- Symbolic links and loops.
- SUID/SGID.
- Linux capabilities.
- Immutable and append-only attributes.
- Unknown UID/GID ownership.
- Objects removed or replaced during scanning.
- Permission-denied coverage.
- Table, JSON, CSV, and SARIF output.
- Output escaping.
- Kernel feature fallback.

Tests that require privileges or filesystem-specific features must clearly
declare their prerequisites and skip safely when unavailable.

Do not fetch test dependencies from an unpinned branch. Pin dependencies to a
specific release or commit.

## Pull requests

A pull request should explain:

- What changed.
- Why it changed.
- User-visible impact.
- Security impact.
- Compatibility impact.
- Tests executed.
- Known limitations.

The pull request should be small enough to review accurately.

## Documentation

Update all affected public contracts:

- `README.md`
- CLI help.
- Manual page.
- Shell completions.
- Structured-output schema documentation.
- `CHANGELOG.md`
- Architecture or threat-model documentation when applicable.

An option must not exist in only one of the parser, help, manual, completions,
or README.

## Performance changes

Performance contributions require a reproducible benchmark description:

- CPU.
- RAM.
- Kernel.
- Filesystem.
- Compiler and build type.
- Dataset shape.
- Object count.
- Enabled analyzers.
- Thread count.
- Before and after measurements.
- Peak memory.

Optimize only after correctness and coverage semantics are established.

## License

By contributing, you agree that your contribution is distributed under
GPL-3.0-only.
