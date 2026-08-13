set shell := ["bash", "-euo", "pipefail", "-c"]

build_root := "build"

# Mostrar recetas disponibles.
default:
    @just --list

# Comprobar las herramientas del entorno.
doctor:
    @printf '%-18s %s\n' "CMake" "$(cmake --version 2>/dev/null | head -1 || echo missing)"
    @printf '%-18s %s\n' "CTest" "$(ctest --version 2>/dev/null | head -1 || echo missing)"
    @printf '%-18s %s\n' "Ninja" "$(ninja --version 2>/dev/null || echo missing)"
    @printf '%-18s %s\n' "Compiler" "$(c++ --version 2>/dev/null | head -1 || echo missing)"
    @printf '%-18s %s\n' "ccache" "$(command -v ccache || echo optional-not-found)"
    @printf '%-18s %s\n' "mold" "$(command -v mold || echo optional-not-found)"
    @printf '%-18s %s\n' "lld" "$(command -v ld.lld || echo optional-not-found)"
    @printf '%-18s %s\n' "clang-format" "$(command -v clang-format || echo optional-not-found)"
    @printf '%-18s %s\n' "clang-tidy" "$(command -v clang-tidy || echo optional-not-found)"
    @printf '%-18s %s\n' "perf" "$(command -v perf || echo optional-not-found)"

# Configurar uno de estos perfiles:
# debug, release, relwithdebinfo o minsizerel.
configure profile="debug":
    #!/usr/bin/env bash
    set -euo pipefail

    case "{{profile}}" in
        debug)
            build_type="Debug"
            ;;
        release)
            build_type="Release"
            ;;
        relwithdebinfo|profile)
            build_type="RelWithDebInfo"
            ;;
        minsizerel)
            build_type="MinSizeRel"
            ;;
        *)
            printf 'Perfil desconocido: %s\n' "{{profile}}" >&2
            printf 'Perfiles: debug, release, relwithdebinfo, minsizerel\n' >&2
            exit 2
            ;;
    esac

    build_dir="{{build_root}}/{{profile}}"

    cmake \
        -S . \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE="$build_type" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

    if [[ -f "$build_dir/compile_commands.json" ]]; then
        ln -sfn "$build_dir/compile_commands.json" compile_commands.json
    fi

# Configurar y compilar.
build profile="debug":
    just configure "{{profile}}"
    cmake --build "{{build_root}}/{{profile}}" --parallel

# Ejecutar los tests registrados con CTest.
test profile="debug":
    just build "{{profile}}"
    ctest \
        --test-dir "{{build_root}}/{{profile}}" \
        --output-on-failure \
        --parallel

# Compilar y ejecutar el binario principal kls.
run profile="debug":
    #!/usr/bin/env bash
    set -euo pipefail

    just build "{{profile}}"

    executable="$(
        find "{{build_root}}/{{profile}}" \
            -type f \
            -name kls \
            -perm -111 \
            -print \
            -quit
    )"

    if [[ -z "$executable" ]]; then
        printf 'No se encontró el ejecutable kls en %s\n' \
            "{{build_root}}/{{profile}}" >&2

        printf '\nEjecutables encontrados:\n' >&2

        find "{{build_root}}/{{profile}}" \
            -type f \
            -perm -111 \
            -print >&2

        exit 1
    fi

    "$executable"

# Compilación optimizada.
release:
    just build release

# Compilación optimizada con símbolos para profiling.
profile:
    just build relwithdebinfo

# AddressSanitizer y UndefinedBehaviorSanitizer.
sanitize:
    #!/usr/bin/env bash
    set -euo pipefail

    build_dir="{{build_root}}/sanitize"
    sanitizer_flags="-fsanitize=address,undefined -fno-omit-frame-pointer"

    cmake \
        -S . \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_C_FLAGS="$sanitizer_flags" \
        -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
        -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
        -DCMAKE_SHARED_LINKER_FLAGS="$sanitizer_flags"

    cmake --build "$build_dir" --parallel

    ctest \
        --test-dir "$build_dir" \
        --output-on-failure \
        --parallel

# Compilación instrumentada con clang-tidy.
tidy-build:
    #!/usr/bin/env bash
    set -euo pipefail

    command -v clang-tidy >/dev/null || {
        printf 'clang-tidy no está instalado.\n' >&2
        exit 1
    }

    build_dir="{{build_root}}/tidy"

    cmake \
        -S . \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_CXX_CLANG_TIDY=clang-tidy

    cmake --build "$build_dir" --parallel

# Formatear todos los archivos C y C++ del proyecto.
format:
    #!/usr/bin/env bash
    set -euo pipefail

    command -v clang-format >/dev/null || {
        printf 'clang-format no está instalado.\n' >&2
        exit 1
    }

    mapfile -d '' files < <(
        find include src tests \
            -type f \
            \( \
                -name '*.c' \
                -o -name '*.cc' \
                -o -name '*.cpp' \
                -o -name '*.h' \
                -o -name '*.hh' \
                -o -name '*.hpp' \
            \) \
            -print0
    )

    if (( ${#files[@]} == 0 )); then
        printf 'No se encontraron archivos para formatear.\n'
        exit 0
    fi

    clang-format -i "${files[@]}"

# Comprobar formato sin modificar archivos.
format-check:
    #!/usr/bin/env bash
    set -euo pipefail

    command -v clang-format >/dev/null || {
        printf 'clang-format no está instalado.\n' >&2
        exit 1
    }

    mapfile -d '' files < <(
        find include src tests \
            -type f \
            \( \
                -name '*.c' \
                -o -name '*.cc' \
                -o -name '*.cpp' \
                -o -name '*.h' \
                -o -name '*.hh' \
                -o -name '*.hpp' \
            \) \
            -print0
    )

    if (( ${#files[@]} == 0 )); then
        printf 'No se encontraron archivos para comprobar.\n'
        exit 0
    fi

    clang-format \
        --dry-run \
        --Werror \
        "${files[@]}"

# Validación habitual antes de hacer commit.
check:
    just format-check
    just test debug

# Instalar utilizando el prefijo indicado.
install prefix="$HOME/.local":
    just build release
    cmake \
        --install "{{build_root}}/release" \
        --prefix "{{prefix}}"

# Eliminar builds y compile_commands.json.
clean:
    rm -rf "{{build_root}}"
    rm -f compile_commands.json
