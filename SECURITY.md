# Security Policy

## Project status

`kls` is experimental software. Security boundaries, CLI behavior, finding
schemas, and compatibility guarantees may change before `1.0.0`.

## Supported versions

Security fixes are provided for the latest development release and the current
default branch on a best-effort basis.

| Version | Supported |
| --- | --- |
| Latest `0.x` release | Yes |
| Default branch | Yes |
| Older experimental releases | No guaranteed support |

A formal long-term support policy may be introduced after `1.0.0`.

## Reporting a vulnerability

Use GitHub Issues for normal defects, incorrect findings, documentation
problems, and feature requests.

Do **not** open a public issue for a suspected vulnerability that could affect
users running `kls`, especially when it involves:

- Memory safety.
- Arbitrary code execution.
- Path traversal or audit-root escape.
- Symlink handling.
- Privilege boundaries.
- Unsafe parsing of filenames, extended attributes, or filesystem metadata.
- Terminal or structured-output injection.
- Denial of service against privileged or automated audits.
- Incorrect behavior when scanning attacker-controlled directory trees.

Report these privately through GitHub Private Vulnerability Reporting or a
repository security advisory.

Include, when possible:

- A concise description.
- Affected version or commit.
- Kernel and filesystem.
- Whether `kls` ran as root.
- Reproduction steps.
- Expected and observed behavior.
- Security impact.
- A minimal test tree or fixture.
- Any proposed mitigation.

## Disclosure process

The maintainers will:

1. Confirm receipt when possible.
2. Reproduce and assess the report.
3. Prepare a fix and regression test.
4. Coordinate disclosure when the issue is confirmed.
5. Credit the reporter unless anonymity is requested.

No fixed response-time guarantee is currently offered.

## Security scope

`kls` audits local Linux filesystem metadata and related security conditions.
It may run against attacker-controlled directory trees and may be executed with
elevated privileges. The local nature of the tool does not remove security
risk from its own parser, traversal engine, analyzers, or renderers.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for detailed assumptions,
mitigations, and residual risks.
