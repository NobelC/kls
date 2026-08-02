set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

doctor:
    @printf '%-16s %s\n' 'CMake' "$(cmake --version | sed -n '1p')"
    @printf '%-16s %s\n' 'Ninja' "$(ninja --version)"
    @printf '%-16s %s\n' 'GCC' "$(g++ --version | sed -n '1p')"
    @printf '%-16s %s\n' 'Clang' "$(clang++ --version | sed -n '1p')"
    @printf '%-16s %s\n' 'ccache' "$(ccache --version | sed -n '1p')"
    @printf '%-16s %s\n' 'lld' "$(ld.lld --version | sed -n '1p')"
    @printf '%-16s %s\n' 'GDB' "$(gdb --version | sed -n '1p')"
    @printf '%-16s %s\n' 'Valgrind' "$(valgrind --version)"
    @printf '%-16s %s\n' 'perf' "$(perf version)"
    @printf '%-16s %s\n' 'strace' "$(strace --version | sed -n '1p')"

configure preset="clang-debug":
    cmake --preset "{{preset}}"
    ln -sfn "build/{{preset}}/compile_commands.json" compile_commands.json

build preset="clang-debug": (configure preset)
    cmake --build --preset "{{preset}}" --parallel

run preset="clang-debug" *args: (build preset)
    "./build/{{preset}}/kls" {{args}}

test preset="clang-tests": (build preset)
    ctest --preset "{{preset}}"

check:
    cmake --workflow --preset check

asan:
    cmake --workflow --preset sanitize

tsan:
    cmake --workflow --preset thread

release compiler="clang":
    just build "{{compiler}}-release"

profile-build:
    just build clang-profile

debug *args: (build "clang-debug")
    gdb --args ./build/clang-debug/kls {{args}}

gdb-tui *args: (build "clang-debug")
    gdb -tui --args ./build/clang-debug/kls {{args}}

valgrind *args: (build "clang-debug")
    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./build/clang-debug/kls {{args}}

perf-stat *args: (build "clang-profile")
    perf stat ./build/clang-profile/kls {{args}}

perf-record *args: (build "clang-profile")
    mkdir -p .project-picker-logs
    perf record --call-graph dwarf -o .project-picker-logs/perf.data ./build/clang-profile/kls {{args}}
    perf report -i .project-picker-logs/perf.data

trace *args: (build "clang-debug")
    mkdir -p .project-picker-logs
    strace -f -yy -s 256 -o .project-picker-logs/strace.log ./build/clang-debug/kls {{args}}
    @printf 'Log: %s\n' '.project-picker-logs/strace.log'

format-check:
    find src include tests -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0 | xargs -0 -r clang-format --dry-run --Werror

format:
    find src include tests -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0 | xargs -0 -r clang-format -i

tidy: (configure "clang-debug")
    if command -v run-clang-tidy >/dev/null 2>&1; then run-clang-tidy -p build/clang-debug; else find src tests -type f -name '*.cpp' -print0 | xargs -0 -r clang-tidy -p build/clang-debug; fi

ccache-stats:
    ccache --show-stats

targets preset="clang-debug": (configure preset)
    cmake --build --preset "{{preset}}" --target help

clean:
    @read -r -p 'Eliminar build/, compile_commands.json y logs? [y/N] ' answer; if [[ "$answer" =~ ^[yY]$ ]]; then rm -rf build compile_commands.json .project-picker-logs; else echo 'Cancelado.'; fi
