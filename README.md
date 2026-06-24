# kls (Security-ls)

**"What's in here, and should I be worried?"**

`kls` is a directory listing tool designed under the Unix philosophy: one tool, one responsibility, done to perfection. Unlike `exa` (colors) or `lsd` (icons), `kls` focuses on **security and risk visibility**.

---

## Philosophy
`kls` doesn't try to be an editor or a network monitor. Its sole purpose is to audit your directories and report security anomalies in real-time.

- ✅ **Read-only. Report-only.**
- ❌ No file copying.
- ❌ No file deletion.
- ❌ Non-destructive.

## Key Features
- **Health-check by default**: Every listing includes a security health analysis.
- **Risk Detection**: Identifies SUID/SGID files, world-writable permissions, broken symlinks, and Linux capabilities.
- **Attack Surface Analysis**: A consolidated summary of the total risk for the directory.
- **Timeline Analysis**: Detects timestamp anomalies (ctime < mtime) and files modified in the future.

## Quick Start

```bash
kls                # Listing with security analysis by default
kls -l             # Long format with security metadata
kls --only-alerts  # Show only files with security risks
kls --sort=severity # Most dangerous files first
```

## 📦 Installation & Packaging

`kls` supports multiple distribution formats and architectures (including native **x86_64** and **ARM64**). Choose the method that best fits your system:

| Platform / Distro | Method | Command / Package |
| :--- | :--- | :--- |
| **Arch Linux** | AUR Helper | `yay -S kls` or `paru -S kls` |
| **Arch Linux** | AUR (Manual) | `git clone https://aur.archlinux.org/kls.git && cd kls && makepkg -si` |
| **Any Linux / macOS** | Build from Source | `cmake -B build ... && sudo cmake --install build` |

---

### 1. 🏔️ Arch Linux (via AUR)

`kls` is officially maintained in the Arch User Repository.

#### Using an AUR Helper (Recommended)
```bash
yay -S kls
# Or:
paru -S kls
```

#### Manual installation from AUR
```bash
git clone https://aur.archlinux.org/kls.git
cd kls
makepkg -si
```

---

### 4. 🛠️ Build from Source (Any POSIX System)

#### Requirements
*   **CMake 3.15+**
*   **C++20 compatible compiler** (GCC 13+ or Clang 16+)
*   **gzip** (Optional, to automatically compress manual pages)

#### 🚀 Production Build & Installation (Recommended for users)
Configure the project in **Release** mode (disabling debug sanitizers for maximum performance) and install it globally:

```bash
# 1. Configure in Release mode (install prefix /usr)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_SANITIZERS=OFF -DCMAKE_INSTALL_PREFIX=/usr

# 2. Compile (multi-threaded)
cmake --build build --parallel

# 3. Install globally (requires root permissions)
sudo cmake --install build
```

#### 🧑‍💻 Developer Build (With Sanitizers & Debug symbols)
For testing, debugging, or active development, compile with sanitizers and debug symbols enabled:

```bash
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build
```

---

### 🧹 Uninstallation

To completely remove `kls`, its shell completions, and the manual pages from your system:

```bash
sudo cmake --build build --target uninstall
```

---

### 🔒 Cryptographic Verification

Because `kls` is a security auditing tool, we cryptographically sign all release assets using GPG. Before installing, you can verify your package's integrity:

```bash
# Verify a downloaded package using its detached signature (.asc)
gpg --verify kls-0.1.1-Linux-x86_64.deb.asc kls-0.1.1-Linux-x86_64.deb
```
For detailed instructions on importing public keys and managing verification, see our [Release Signing & Verification Guide](docs/RELEASE-SIGNING.md).


## Architecture

`kls` is built with performance and safety in mind. It utilizes a custom multi-threaded traversal engine that leverages `statx` for modern Linux metadata collection.

The processing pipeline is divided into:
1. **Collection**: Concurrent filesystem scanning.
2. **Filtering**: Efficient glob-based reduction.
3. **Sorting**: Flexible result ordering.
4. **Presentation**: User-friendly terminal rendering.

For more technical details, see the [List Architecture Documentation](docs/LIST-ARCHITECTURE.md).

---

## License
MIT
