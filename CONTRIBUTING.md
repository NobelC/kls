# Contributing to kls

kls is a security-focused directory listing tool.

## Philosophy

- One tool, one responsibility.
- Security-first visibility.
- Read-only, report-only. kls never modifies the filesystem.

---

## Before writing any code

Open an issue first. Describe what you want to change and why.
I'll let you know if it's something I want before you spend time on it.

---

## Architecture overview

Understanding the pipeline is mandatory before contributing anything.

Every invocation follows this exact sequence:
argv → tokenization → parsing → validation → executor → pipeline

**tokenization** — splits raw strings into typed tokens (OPTION, LITERAL, POSITIONAL).

**parsing** — normalizes tokens against the option registry. Aliases are resolved
here (`-a` → `--all`). Values are attached to their options.

**validation** — enforces conflicts, requirements, type correctness, and
deduplication. Also sorts options by execution category.

**executor** — routes to the correct command handler.

**pipeline (inside LIST_HANDLER)** — four sequential phases:
1. Collection — filesystem traversal, `statx` per entry, populates `FileEntry` vector.
2. Filtering  — `FilteringProcess` handlers reduce the vector.
3. Sorting    — `FilteringProcess` handlers reorder the vector.
4. Presentation — renders to stdout.

---

## How to add a new option

All options live in `src/option-register-information/option-information.cpp`
inside `CreatedOptionData()`.

Every option requires:

- `normalized_name` — the canonical long form (`--my-option`).
- `alias_name` — short form if it has one (`-m`). Optional.
- `data_type` — what value it accepts: `NONE`, `STRING`, `DATE`, `SIZE`, `EXTENSION`.
- `category` — determines execution order and which pipeline phase owns it:
  - `COLLECTION` — controls what gets collected.
  - `FILTERING`  — reduces the entry set.
  - `SORTING`    — reorders the entry set.
  - `PRESENTATION` — controls output format.
  - `GLOBAL`     — system flags handled before the pipeline.
- `conflict_name` — list of options that cannot coexist with this one.
- `requieres_name` — list of options that must be present for this one to work.
- `handler` — a `FilteringProcess` lambda for FILTERING/SORTING, or
  `std::monostate{}` for options the executor or presenter reads directly.

After registering, add the corresponding shell completions in:
- `completions/kls.bash`
- `completions/kls.fish`
- `completions/_kls`

And document it in `docs/LIST-ARCHITECTURE.md` under the correct table.

---

## How to add a new filter

A filter is a `FilteringProcess` — a `std::function<void(FilterStruct&)>`.

`FilterStruct` gives you:
- `entries` — the live `vector<FileEntry>` you operate on.
- `context` — the option's value as `std::any`, cast it to `std::string_view`.

The standard pattern is `std::erase_if` on `entries`. The filter must be
a pure reduction — it never adds entries, never does I/O, never calls
`stat` or any syscall. All data it needs must already be in `FileEntry`.

If your filter needs data that `LongRecolection` does not currently populate,
extend `LongRecolection` first, not the filter.

---

## How to add a new security alert

Security alerts are `HealthFlag` entries inside `FileEntry::health`.

Each alert has:
- `code`  — snake_case identifier (`"world_writable"`, `"suid_active"`).
- `level` — integer: 1 = info, 2 = medium, 3 = high.

Alerts are populated during the **collection phase** in `LongRecolection`,
not during filtering. The mode bits and metadata are already available from
`statx` — no extra syscall should be needed for most alerts.

The `--only-alerts` filter then reads `FileEntry::health` and erases
entries with an empty health vector.

If your alert requires a syscall not already in the collection path
(e.g. `getxattr` for capabilities), gate it behind its own flag so the
default path pays zero cost.

---

## The FileEntry contract

`FileEntry` is the contract between all four phases. Its fields are
populated once during collection and are read-only from that point forward.

Before adding a field to `FileEntry`, ask:
- Is this data available from `statx` with the current mask?
- Is it needed by more than one phase or option?
- Does adding it increase the struct size in a way that matters at scale?

If the answer to the last question is yes, bring it up in the issue first.

---

## Code style

- C++20. STL only. No external dependencies. No exceptions.
- No raw owning pointers. No `new`/`delete`.
- Prefer `std::string_view` over `const std::string&` for read-only string
  parameters. Pass `string_view` by value, not by `const&`.
- `static` for file-scoped variables, not `inline`.
- Code should be readable without comments — but comments are welcome
  when they add real context, especially for non-obvious syscall behavior.
- For performance changes: include a comment with before/after timing.
- For behavior changes: include a comment explaining what changed and why.

---

## Testing

Every new option or filter requires at least one test in the appropriate
test file under `tests/`.

- `TOKENIZATION_TEST.cpp` — new token types or edge cases in raw parsing.
- `PARSING_TEST.cpp`      — option normalization, value attachment, aliases.
- `VALIDATION_TEST.cpp`   — conflicts, requires, type validation.
- `EXECUTOR_TEST.cpp`     — end-to-end behavior visible in stdout.

Tests must pass under ASan + UBSan (the CI runs with `-fsanitize=address,undefined`).

Do not commit empty test files.

---

## Bug reports

**Error name / description**
What is the error or unexpected behavior.

**Command executed**
kls [options] [args]

**Output received**
Paste the actual output or error message.

**Expected behavior**
What you expected kls to do instead.

**System**
OS, kernel version, and compiler version.

---

## Pull requests

- One PR per fix or improvement.
- Reference the issue it closes: `Closes #N`.
- Keep changes focused — do not mix unrelated fixes in the same PR.
- If your PR touches `FileEntry`, the pipeline, or `LongRecolection`,
  run the speed benchmarks (`SPEED_TEST_LIST`) and include the output
  in the PR description.
