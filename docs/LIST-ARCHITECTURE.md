# List Command Architecture

This document describes the internal architecture of the `list` command in `kls`, focusing on its high-performance multi-threaded engine and security-centric data collection pipeline.

## 1. High-Level Overview

The `list` command follows a decoupled architecture composed of four distinct stages:

1.  **Collection**: Multi-threaded traversal and metadata gathering using `statx`.
2.  **Filtering**: Removal of entries based on user criteria (glob patterns, dates, etc.).
3.  **Sorting**: Reordering of the final set (by name, size, type, or security severity).
4.  **Presentation**: Rendering the data to the terminal in various formats.

---

## 2. Multi-threaded Traversal Engine

The core of the `list` command is a high-concurrency engine designed to maximize I/O throughput when exploring large directory trees.

### Components
- **Pending Queue (`pending_dirs`)**: A thread-safe queue of directories waiting to be explored.
- **Worker Threads**: A pool of threads (up to `MAX_THREAD` or CPU core count) that consume from the queue.
- **Atomic Counters**: `working_threads` tracks active workers to determine when the entire tree has been processed.

### Algorithm
- Every worker pops a directory, opens it with `opendir()`, and iterates through its entries.
- Files are added to a local `file_entry_temp` vector.
- Subdirectories (if `--recursive` is active) are added to a local `temp_pending_dir` vector.
- To minimize lock contention, workers perform **batch transfers** to the global queue and results vector after completing a directory.

---

## 3. Metadata Collection (`statx`)

`kls` uses the modern Linux `statx(2)` system call. This provides several advantages:
- **Birth Time**: Access to file creation time (btime), which is unavailable in the older `stat` call.
- **Performance**: Improved efficiency on modern filesystems and network mounts by requesting only necessary metadata masks.

---

## 4. Security-Centric Design

### The `FileEntry` Struct
Every file is represented by a `FileEntry` object, which stores:
- POSIX metadata (UID, GID, Mode, Inode).
- Security flags (SUID/SGID detection).
- Symlink resolution status (broken link detection).
- Custom health alerts (tracked in the `health` vector).

### Recursive Depth Control
Users can control the intensity of the traversal using the `--depth` flag, preventing accidental "infinite" loops or excessive I/O on extremely deep structures.

---

## 5. Usage & Options

### Collection
| Option              | Alias | Description                   |Status|
| :------------------ | :---- | :---------------------------- |------|
| `--all`             | `-a`  | Include hidden files          |  ✅  | 
| `--recursive`       | `-r`  | Descend into subdirectories   |  ✅  |
| `--depth=N`         | `-d`  | Maximum depth in recursion    |  ✅  |
| `--dirs-only`       |       | Directories only              |  ✅  |
| `--files-only`      |       | Regular files only            |  ✅  |
| `--follow-symlinks` |       | Resolve symlinks when listing |      |

### General Filtering
| Option                             | Alias | Description                     |Status|
| :--------------------------------- | :---  | :------------------------------ |------|
| `--ext=cpp,hpp`                    |       | Filter by extensions            |  ✅  |
| `--larger-than=N`                  |       | Files larger than N (1KB, 2MB)  |  ✅  |
| `--smaller-than=N`                 |       | Files smaller than N            |  ✅  |
| `--modified-after=YEAR-MONTH-DAY`  |       | Modified in the last N days     |  ✅  |
| `--modified-before=YEAR-MONTH-DAY` |       | Modified more than N days ago   |  ✅  |
| `--name=pattern`                   |       | Filter by glob name pattern     |  ✅  |
| `--owner=user`                     |       | Filter by owner                 |  ✅  |
| `--group=group`                    |       | Filter by group                 |  ✅  |
| `--min-links=N`                    |       | Files with at least N hardlinks |  ✅  |

### Security — Filtering
| Option                    | Alias | Description                                   |Status|
| :------------------------ | :---- | :-------------------------------------------- |------|
| `--only-alerts`           |       | Only show entries with alerts                 |      |
| `--only-suid`             |       | Only files with active SUID                   |      |
| `--only-sgid`             |       | Only files with active SGID                   |      | 
| `--only-world-writable`   |       | Only files writable by everyone               |      |
| `--only-world-executable` |       | Only files executable by everyone             |      |
| `--only-capabilities`     |       | Only files with capabilities                  |      |
| `--only-orphans`          |       | Only UID/GID with no entry in passwd/group    |      |
| `--only-broken`           |       | Only broken symlinks                          |      |
| `--only-future`           |       | Only files with mtime in the future           |      |
| `--only-empty`            |       | Only 0-byte files                             |      |
| `--only-sticky`           |       | Only files with sticky bit on non-directories |      |
| `--only-anomalies`        |       | Only temporal anomalies (ctime < mtime)       |      |
| `--only-ancient=N`        |       | Only files not modified in more than N days   |      |
| `--exclude-alerts`        |       | Show everything except entries with alerts    |      |
| `--min-severity=N`        |       | Only alerts of level N or higher (1, 2, 3)    |      | 

### Security — Analysis
| Option             | Alias | Description                                  | Status |
| :----------------- | :---- | :------------------------------------------- |------- |
| `--health`         |       | Enabled by default — full health analysis    |   ✅   |
| `--no-health`      |       | Disable health analysis                      |   ✅   |
| `--capabilities`   |       | Show Linux capabilities per entry            |        |
| `--acl`            |       | Show extended ACLs if they exist             |        |
| `--attack-surface` |       | Summary of the directory's attack surface    |        |
| `--timeline`       |       | Temporal anomaly analysis                    |        |
| `--duplicates`     |       | Detect files with identical content          |        |
| `--sticky`         |       | Explicitly mark sticky bit                   |        |
| `--immutable`      |       | Detect files with immutable flag (chattr +i) |        |
| `--setuid-tree`    |       | List all SUIDs in the recursive tree         |        |
| `--world-tree`     |       | List all world-writable in the tree          |        |

### Sorting
| Option            | Alias | Description                      | Status |
| :---------------- | :---- | :------------------------------- |------- |
| `--sort=name`     |       | By name (default)                |   ✅   |
| `--sort=size`     |       | By size                          |   ✅   |
| `--sort=date`     |       | By modification date             |   ✅   |
| `--sort=ext`      |       | By extension                     |   ✅   |
| `--sort=type`     |       | Directories first                |   ✅   |
| `--sort=severity` |       | By security alert level          |   ✅   |
| `--sort=owner`    |       | By owner                         |   ✅   |
| `--reverse`       |       | Reverse order                    |   ✅   |
| `--dirs-first`    |       | Directories always first         |   ✅   |
| `--alerts-first`  |       | Entries with alerts always first |   ✅   |

### Presentation
| Option              | Alias | Description                                  | Status |
| :------------------ | :---  | :--------------------------------------------|------  |
| `--no-header`       |       | Suppress headers                             |   ✅   |
| `--tree`            |       | Hierarchical view                            |        |
| `--grid`            |       | Multiple columns                             |        |
| `--compact`         |       | Names only, maximum density                  |        |
| `--summary`         |       | Statistics only, without listing entries     |        |
| `--security-report` |       | Consolidated security report at the end      |        |
| `--no-color`        |       | No ANSI colors                               |        |
| `--inode`           |       | Show inode number                            |        |
| `--nlinks`          |       | Show number of hardlinks                     |        |
| `--blocks`          |       | Show disk blocks used                        |        |
| `--octal`           |       | Show permissions in octal besides symbolic   |        |
| `--numeric-ids`     |       | Show numeric UID/GID instead of names        |        |
| `--full-path`       |       | Show full absolute path                      |        |
| `--timestamp=mtime` |       | Which timestamp to show: mtime, ctime, btime |        |
| `--time-format=iso` |       | Time format: iso, relative, epoch            |        |

### Structured Output
| Option               | Alias | Description                            | Status |
| :------------------- | :---- | :------------------------------------- |------- |
| `--format=json`      |       | Parseable JSON output                  |        |
| `--format=csv`       |       | CSV output                             |        |
| `--format=ndjson`    |       | One JSON object per line               |        |
| `--fields=name,size` |       | Fields to include in structured output |        |

### System
| Option         | Alias | Description                        | Status |
| :------------- | :---- | :--------------------------------- |--------|
| `--help`       | `-h`  | Help                               |   ✅   |
| `--version`    | `-v`  | Version                            |   ✅   |
| `--quiet`      | `-q`  | Errors only                        |        |
| `--no-heading` |       | No directory heading               |        |
| `--threads=N`  |       | Number of threads (default: auto)  |        |
| `--si`         |       | Use powers of 1000 instead of 1024 |        |


## 6. Optimization Details

- **Batch Commit**: Results are pushed to the global vector in chunks to reduce mutex lock/unlock overhead.
- **String Pre-allocation**: `full_path` strings use `reserve(PATH_MAX)` to avoid frequent reallocations.
- **Condition Variables**: Threads sleep when the queue is empty, ensuring zero CPU wastage.
