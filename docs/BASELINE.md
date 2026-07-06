# Core Baseline

Branch:

```text
stabilize/core-baseline
```

Planned release:

```text
0.2.0
```

## Rule

Do not add new security detectors until the scanner, unified finding model,
CLI, tests, exit codes, and documentation are coherent.

## 1. Critical corrections

- [ ] Remove the duplicate `PrintHealthFlags` symbol.
- [ ] Implement and use `PrintCapabilityFlags`.
- [ ] Unify `--only-capabilities` naming.
- [ ] Ensure capability findings reach the renderer.
- [ ] Clear all finding state when entries are reused.
- [ ] Remove or implement redundant capability booleans.
- [ ] Correct passwd buffer sizing constants.
- [ ] Return nonzero status for invalid or inaccessible targets.
- [ ] Return zero for `--help` and `--version`.
- [ ] Stop silently ignoring directory-open errors.

## 2. CLI contract

- [ ] Create one declarative option specification.
- [ ] Generate or validate parser, help, man page, and completions from it.
- [ ] Reconcile `--file-only` and `--files-only`.
- [ ] Reconcile `--sort=modified` and `--sort=date`.
- [ ] Reconcile `--follow-symlink` and `--follow-symlinks`.
- [ ] Register or remove `-l` and `--long`.
- [ ] Register or remove `--health`.
- [ ] Implement or remove `--stats`.
- [ ] Implement or remove `--quiet`.
- [ ] Implement or remove `--verbose`.
- [ ] Implement TTY-aware color.
- [ ] Validate sort criteria.
- [ ] Validate severity values.
- [ ] Parse numbers with `std::from_chars`.
- [ ] Reject overflow, negatives, and trailing data.

## 3. Exit status

- [ ] `0`: audit completed.
- [ ] `2`: invalid CLI.
- [ ] `3`: incomplete audit.
- [ ] `4`: internal failure.
- [ ] `5`: configured threshold exceeded.
- [ ] Implement `--fail-on`.
- [ ] Implement `--fail-on-findings`.
- [ ] Add exit-code integration tests.

## 4. Unified findings

- [ ] Introduce `Finding`.
- [ ] Introduce `FindingId`.
- [ ] Introduce `FindingCategory`.
- [ ] Introduce `Severity`.
- [ ] Introduce structured `Evidence`.
- [ ] Replace separate health and capability vectors.
- [ ] Preserve existing IDs where semantics are unchanged.
- [ ] Document all IDs.
- [ ] Make findings immutable after creation.
- [ ] Keep informational findings distinct from risks.

## 5. Audit model

- [ ] Rename listing-oriented internals.
- [ ] Accept one directory target.
- [ ] Reject or explicitly define file targets.
- [ ] Audit recursively.
- [ ] Cross mount points.
- [ ] Exclude `/proc`, `/sys`, `/dev`, and `/run` by default.
- [ ] Report exclusions as coverage.
- [ ] Do not follow symlinks by default.
- [ ] Detect broken symlinks.
- [ ] Detect target escapes.
- [ ] Detect loops.

## 6. Descriptor-relative scanner

- [ ] Acquire root directory descriptor once.
- [ ] Add RAII descriptor type.
- [ ] Replace absolute-path operations with directory-relative operations.
- [ ] Use `statx` relative to parent descriptors.
- [ ] Capture device and inode identity.
- [ ] Capture mount ID when available.
- [ ] Revalidate identity for multi-step analysis.
- [ ] Mark changed objects unstable.
- [ ] Record vanished objects.
- [ ] Add Linux `4.11` compatible mode.
- [ ] Add Linux `5.6+` full mode using `openat2`.
- [ ] Report active mode and unavailable features.
- [ ] Bound file descriptors.

## 7. Coverage

- [ ] Add `CoverageReport`.
- [ ] Count directories visited.
- [ ] Count objects discovered.
- [ ] Count objects inspected.
- [ ] Count objects skipped.
- [ ] Count permission failures.
- [ ] Count vanished objects.
- [ ] Count unstable objects.
- [ ] Count unsupported attributes.
- [ ] Count pseudo-filesystem exclusions.
- [ ] Count resource-limit failures.
- [ ] Preserve diagnostics for structured output.
- [ ] Distinguish clean audit from incomplete audit.

## 8. Analyzers

- [ ] Extract permission analysis.
- [ ] Extract ownership analysis.
- [ ] Extract capability analysis.
- [ ] Extract symlink analysis.
- [ ] Extract timestamp analysis.
- [ ] Extract filesystem-flag analysis.
- [ ] Extract device-node analysis.
- [ ] Extract integrity analysis.
- [ ] Remove printing from analyzers.
- [ ] Remove CLI knowledge from analyzers.
- [ ] Declare analyzer metadata requirements.
- [ ] Reuse descriptors across analyzers.

## 9. Renderers

- [ ] Table renderer.
- [ ] JSON renderer.
- [ ] CSV renderer.
- [ ] SARIF renderer.
- [ ] Default coverage summary.
- [ ] Severity summary.
- [ ] Findings-only default.
- [ ] `--inventory`.
- [ ] `--details`.
- [ ] `--summary`.
- [ ] `--min-severity`.
- [ ] `--category`.
- [ ] Escape terminal control characters.
- [ ] Validate JSON.
- [ ] Quote CSV correctly.
- [ ] Validate SARIF.
- [ ] Add schema version.
- [ ] Disable color outside TTY.

## 10. Concurrency

- [ ] Replace the single consumer with a real worker pool.
- [ ] Choose worker count automatically from CPU availability.
- [ ] Cap worker count.
- [ ] Add bounded queue.
- [ ] Add backpressure.
- [ ] Add worker-local result buffers.
- [ ] Merge results after collection.
- [ ] Add cancellation.
- [ ] Propagate worker failures.
- [ ] Measure descriptor and memory limits.

## 11. Tests and CI

- [ ] Enable `BUILD_TESTING`.
- [ ] Enable CTest.
- [ ] Pin GoogleTest.
- [ ] GCC Debug.
- [ ] GCC Release.
- [ ] Clang Debug.
- [ ] Clang Release.
- [ ] ASan.
- [ ] UBSan.
- [ ] Unit tests.
- [ ] Integration tests.
- [ ] Install smoke test.
- [ ] Uninstall smoke test.
- [ ] x86_64 release artifact.
- [ ] AArch64 release artifact.
- [ ] ext4 test coverage.
- [ ] Old-kernel feature-fallback tests where practical.

## 12. Build and repository conventions

- [ ] Use target-scoped CMake options.
- [ ] Use C++20.
- [ ] Use `clang-format`.
- [ ] Introduce `clang-tidy`.
- [ ] Use `std::expected` or explicit results in the core.
- [ ] Remove `std::any`.
- [ ] Remove mutable global registries.
- [ ] Minimize runtime dependencies.
- [ ] Use Conventional Commits.
- [ ] Follow Semantic Versioning.
- [ ] Use Keep a Changelog.
- [ ] Set all package metadata to GPL-3.0-only.
- [ ] Remove AUR claims.
- [ ] Remove DEB/RPM claims.
- [ ] Remove macOS/POSIX claims.

## 13. Documentation acceptance

- [ ] README separates current, baseline, and planned behavior.
- [ ] SECURITY defines private reporting.
- [ ] CONTRIBUTING defines code and commit conventions.
- [ ] CHANGELOG contains `0.2.0`.
- [ ] Architecture matches implementation.
- [ ] Threat model matches implemented defenses.
- [ ] Help, man page, completions, and README agree.
- [ ] No unsupported performance claims.
- [ ] No unsupported filesystem claims.

## Completion criteria

The baseline is complete when:

- [ ] GCC and Clang builds pass.
- [ ] Sanitizers pass.
- [ ] Tests pass.
- [ ] CI is required.
- [ ] No duplicate symbols exist.
- [ ] The CLI has one source of truth.
- [ ] Capabilities are normal findings.
- [ ] Exit codes match the public contract.
- [ ] Coverage is reported.
- [ ] The scanner is descriptor-relative.
- [ ] Kernel mode is reported.
- [ ] Symlink policy is enforced.
- [ ] Table, JSON, CSV, and SARIF pass tests.
- [ ] Documentation contains no unimplemented guarantees.
