#pragma once
#include <any>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// ============================================================================
// TIPOS DE DATO QUE RECIBEN LAS OPCIONES
// ============================================================================

enum class TypeDataReceived : std::uint8_t {
  DATE,      // Fecha ISO: 2024-01-01
  SIZE,      // Tamaño con unidad: 10MB, 500KB
  EXTENSION, // String genérico: plain/json/csv, glob, campo, etc.
  NONE,      // Flag booleano, no recibe valor
  STRING,
};

// ============================================================================
// CATEGORÍA DE EJECUCIÓN
// Define el orden cronológico en que se ejecutan las opciones
// ============================================================================

enum class OptionCategory : std::uint8_t {
  COLLECTION = 0, // Recolecta datos
  FILTERING =1, // Reduce el set
  SORTING = 2,      // Ordena y agrupa
  PRESENTATION = 3, // Formato de output
  MANIPULATION =4, // Operaciones sobre paths
  CREATION = 5, // Creación de entradas
  GLOBAL =6, // Flags del sistema
};

// ============================================================================
// STRUCTS DE CONTEXTO POR CATEGORÍA
// Cada proceso recibe el struct que corresponde a su categoría
// ============================================================================

// COLLECTION + FILTERING + SORTING
// Todas las opciones que operan sobre el listado de entradas del filesystem
struct HealthFlag {
  std::string code; // "symlink_broken", "world_writable", etc.
  uint8_t level;        // 1=info, 2=medium, 3=high
};

struct FileEntry {
  // 1. Metadatos de POSIX (Tipos primitivos primero para mejor alineación)
  ino_t inode;    // 8 bytes
  uint64_t size;  // 8 bytes
  mode_t mode;    // 4 bytes
  nlink_t nlinks; // 8 bytes (en x86_64)
  uid_t uid;      // 4 bytes (Almacena el ID, no el nombre)
  gid_t gid;      // 4 bytes (Almacena el ID, no el nombre)

  // 2. Flags de estado (Bitfields para ahorrar espacio)
  bool is_directory : 1;
  bool is_symlink : 1;
  bool symlink_broken : 1;
  bool has_capabilities : 1;

  // 3. Tiempos (Usar time_t directamente)
  time_t mtime; // 8 bytes (Fecha modificación)
  time_t btime; // 8 bytes (Fecha creación, solo en algunos FS/Kernel)

  // 4. Strings y Contenedores (Al final, son los más pesados)
  std::string name;
  std::string path;
  std::string symlink_target;
  std::string extension;
  std::vector<HealthFlag> health;
};

struct FilterStruct {
  std::vector<FileEntry> &entries;
  std::any context; // dato extra variable: glob, criterio de sort, profundidad,fecha, tamaño
};

// PRESENTATION
// Opciones que controlan cómo se presenta el output al usuario
struct PresentationStruct {
  bool show_header = true;
  bool long_format = false;
  bool no_color = false;
  enum class Format : std::uint8_t { PLAIN, JSON, CSV } format = Format::PLAIN;
};

// MANIPULATION
// Opciones que controlan el comportamiento de operaciones sobre paths
struct PathStruct {
  std::filesystem::path origin;
  std::filesystem::path destination;
  bool force = false;
  bool dry_run = false;
  bool preserve = false;
  bool skip_existing = false;
  bool no_overwrite = false;
  bool verbose = false;
};

// CREATION
// Opciones que controlan la creación de archivos y directorios
struct CreationStruct {
  std::filesystem::path target;
  bool parents = false;
  bool no_create = false;
  std::optional<std::chrono::sys_seconds> timestamp = std::nullopt;
};

// ============================================================================
// TIPOS DE HANDLER POR CATEGORÍA
// ============================================================================

using FilteringProcess = std::function<void(FilterStruct &)>;
using PresentationProcess = std::function<void(PresentationStruct &)>;
using PathProcess = std::function<void(PathStruct &)>;
using CreationProcess = std::function<void(CreationStruct &)>;

using OptionHandler =
    std::variant<std::monostate,      // GLOBAL — el sistema los maneja, no el
                                      // pipeline
                 FilteringProcess,    // COLLECTION | FILTERING | SORTING
                 PresentationProcess, // PRESENTATION
                 PathProcess,         // MANIPULATION
                 CreationProcess      // CREATION
                 >;

// ============================================================================
// METADATA DE OPCIÓN
// ============================================================================

struct OptionMetaData {
  std::string normalized_name;
  std::string alias_name;
  std::vector<std::string> conflict_name;
  std::vector<std::string> requieres_name = {};
  TypeDataReceived data_type = TypeDataReceived::NONE;
  OptionCategory category;
  OptionHandler hanlder;
};
