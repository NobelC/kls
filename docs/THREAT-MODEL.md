# Threat Model

## Status

This threat model defines the security assumptions for the target
`stabilize/core-baseline` architecture.

`kls` is experimental. This document describes intended defenses and residual
risks, not a certification.

## Security objective

`kls` should safely inspect a Linux directory tree, including a tree controlled
by an untrusted local user, and produce an honest report of findings and audit
coverage.

The tool may be executed as root. Therefore, untrusted filesystem data must be
treated as hostile input.

## Protected properties

The design aims to preserve:

- Process memory safety.
- Containment within the configured audit root.
- Correct association between evidence and filesystem object identity.
- Accurate reporting of incomplete coverage.
- Valid and escaped terminal or structured output.
- Predictable resource consumption.
- No intentional mutation of the audited tree.
- Deterministic exit-status semantics.

## Trusted components

The initial model trusts:

- The Linux kernel.
- The C and C++ runtime.
- The compiler and linked standard libraries.
- The user-provided configuration.
- The process environment unless explicitly sanitized.
- The filesystem implementation to the extent required by kernel interfaces.

A compromised kernel or malicious filesystem implementation can violate these
assumptions.

## Untrusted inputs

Treat as untrusted:

- File and directory names.
- Symlink targets.
- Extended attributes.
- Capability xattrs.
- UID and GID values.
- Timestamps.
- Inode and mount metadata.
- Directory topology.
- Number and size of objects.
- Concurrent filesystem changes.
- NSS responses.
- Terminal control characters.
- Policy files.
- Structured-output destinations.

## Adversary capabilities

An attacker may:

- Create, rename, replace, and remove objects during the audit.
- Construct symlink loops.
- Point symlinks outside the audit root.
- Create deep or extremely wide directory trees.
- Use unusual filenames, invalid bytes, or terminal escape sequences.
- Provide malformed or unexpected extended attributes.
- Deny permissions selectively.
- Create special files.
- Trigger mount or automount behavior.
- Exhaust memory, descriptors, queue capacity, or CPU.
- Change permissions or ownership between inspection steps.
- Replace an inode after pathname discovery.
- Manipulate paths under a directory they control.

## Threats and mitigations

### Path replacement and TOCTOU

**Threat:** An object is discovered by pathname and replaced before a later
metadata, xattr, or content operation. Evidence from different objects could be
combined.

**Mitigations:**

- Use directory-relative operations.
- Hold directory descriptors.
- Capture device, inode, and mount identity.
- Revalidate identity for multi-step analysis.
- Mark inconsistent objects as unstable.
- Do not emit a normal finding from mixed evidence.

**Residual risk:** A live filesystem cannot provide a universal atomic
point-in-time view. Even one metadata request can expose fields from different
moments.

### Symlink escape

**Threat:** A symbolic link causes traversal or inspection outside the intended
audit root.

**Mitigations:**

- Do not follow symlinks by default.
- Inspect the link itself.
- Use `openat2` containment restrictions in full mode.
- Detect and report targets outside the root.
- Require explicit policy before following external targets.
- Track visited identities to prevent loops.

**Residual risk:** Compatible mode on older kernels has weaker path-resolution
controls and must disclose reduced guarantees.

### Magic links and pseudo-filesystems

**Threat:** Dynamic links or pseudo-filesystem behavior exposes objects outside
normal filesystem semantics or causes side effects.

**Mitigations:**

- Exclude `/proc`, `/sys`, `/dev`, and `/run` by default.
- Report exclusions as coverage diagnostics.
- Use magic-link restrictions where supported.
- Avoid opening special objects unless required.

**Residual risk:** Bind mounts or alternate mount layouts can expose dynamic
filesystems at unexpected paths. Path-prefix exclusion alone is insufficient;
filesystem and mount metadata should inform policy.

### Malformed extended attributes

**Threat:** A malformed capability or other xattr causes out-of-bounds access,
misclassification, or denial of service.

**Mitigations:**

- Validate returned size before reinterpretation.
- Decode byte fields explicitly.
- Validate revision and field availability.
- Reject truncated and oversized values.
- Test malformed fixtures.
- Avoid unchecked casts.

### Terminal injection

**Threat:** A filename or xattr contains control characters that alter terminal
state, forge output, or hide findings.

**Mitigations:**

- Escape non-printable characters in table output.
- Never pass untrusted strings as format strings.
- Disable color outside a TTY.
- Escape all structured formats according to their specifications.
- Add renderer regression tests.

### Structured-output injection

**Threat:** Untrusted data breaks JSON, CSV, or SARIF structure.

**Mitigations:**

- Use dedicated serializers.
- Quote and escape CSV fields.
- Validate generated output in tests.
- Include a schema version.
- Keep presentation separate from analyzers.

### Resource exhaustion

**Threat:** A large or adversarial tree exhausts memory, CPU, thread capacity,
or file descriptors.

**Mitigations:**

- Bounded work queues.
- Bounded descriptor pool.
- Automatic but capped worker count.
- Worker-local buffers.
- Depth controls.
- Cancellation.
- Resource-limit diagnostics.
- Streaming output when compatible with requested ordering.

**Residual risk:** Exhaustive auditing of very large trees is inherently
resource-intensive.

### Permission-denied blind spots

**Threat:** Inaccessible objects are silently treated as clean.

**Mitigations:**

- Record every permission-denied event.
- Include it in coverage.
- Return incomplete-audit status when required.
- Explain that root can improve coverage.
- Never infer safety from missing metadata.

### Object disappearance

**Threat:** Files disappear during traversal and are silently omitted.

**Mitigations:**

- Record vanished objects.
- Distinguish disappearance from not-found input.
- Include counts and paths where safely representable.
- Mark the audit incomplete according to policy.

### Mount boundaries

**Threat:** Recursive traversal crosses into unexpected filesystems with
different trust, latency, or semantics.

**Baseline policy:** Cross mount points.

**Mitigations:**

- Record mount identity.
- Include mounted filesystems in coverage.
- Respect pseudo-filesystem exclusion.
- Support a future one-filesystem policy.
- Report unsupported metadata per mount.

### Filesystem-dependent metadata

**Threat:** A filesystem does not provide requested fields, causing false
assumptions.

**Mitigations:**

- Check `statx` masks.
- Treat unavailable fields as unavailable, not zero.
- Report unsupported attributes.
- Maintain a tested-filesystem matrix.
- Avoid claiming support based only on successful compilation.

### NSS and identity lookup

**Threat:** UID/GID name resolution is slow, unavailable, inconsistent, or
controlled by a remote service.

**Mitigations:**

- Keep numeric identity authoritative.
- Cache lookups by numeric ID.
- Separate resolution failure from nonexistent identity.
- Bound lookup work where possible.
- Preserve numeric IDs in structured output.

### Privileged execution

**Threat:** A parser, memory-safety, or traversal flaw has greater impact when
`kls` runs as root.

**Mitigations:**

- Treat all filesystem data as hostile.
- Use sanitizers in development and CI.
- Avoid exceptions and unchecked casts in the core.
- Minimize dependencies.
- Use RAII for descriptors.
- Add privileged integration tests in controlled environments.
- Recommend unprivileged execution when full coverage is unnecessary.

## Read-only limitations

`kls` does not intentionally change contents, permissions, ownership, extended
attributes, or directory entries.

Possible externally observable effects of reading include:

- Access-time updates.
- Automount activation.
- Network filesystem requests.
- Storage wakeups.
- Dynamic pseudo-filesystem behavior.
- Logs or audit events generated by external services.

The implementation should minimize unnecessary opens and use metadata-only
operations where possible.

## Live filesystem versus snapshot

A live audit is best effort. Concurrent changes can prevent a consistent
point-in-time result.

For higher-confidence audits, users should prefer a read-only filesystem
snapshot when their storage system supports one. Snapshot support is not a
core dependency and ext4 does not provide native filesystem snapshots by
itself.

`kls` must still report instability during live scans.

## Non-goals

The threat model does not claim protection against:

- A compromised kernel.
- A malicious compiler or runtime.
- Hardware faults.
- Complete malware detection.
- Runtime process behavior.
- Network attacks unrelated to filesystem inspection.
- Security guarantees for unsupported environments.
- Perfect atomicity on a live filesystem.
- Proof that an object without findings is safe.

## Security testing priorities

- Symlink loops and root escapes.
- Object replacement between inspection steps.
- Malformed capability xattrs.
- Control characters in filenames.
- Deep and wide trees.
- Permission-denied subtrees.
- File disappearance.
- Descriptor exhaustion.
- Queue saturation.
- Unsupported `statx` fields.
- Old-kernel compatibility mode.
- Root execution.
