cmake_minimum_required(VERSION 3.20)
project(detective_core C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ═══════════════════════════════════════════════
# 헤더 경로
# ═══════════════════════════════════════════════
include_directories(${PROJECT_SOURCE_DIR}/include)

# ═══════════════════════════════════════════════
# BLAKE3 내부 라이브러리 (정적 링크)
# ═══════════════════════════════════════════════
set(BLAKE3_SOURCES
    src/internal/blake3.c
    src/internal/blake2b.c
)

add_library(blake3_internal STATIC ${BLAKE3_SOURCES})
target_include_directories(blake3_internal PUBLIC ${PROJECT_SOURCE_DIR}/include)

# ═══════════════════════════════════════════════
# Detective Core 공유 라이브러리 (DLL/SO)
# ═══════════════════════════════════════════════
set(DETECTIVE_CORE_SOURCES
    src/detective_core.c
)

add_library(detective_core SHARED ${DETECTIVE_CORE_SOURCES})
target_link_libraries(detective_core PRIVATE blake3_internal)
target_include_directories(detective_core PUBLIC ${PROJECT_SOURCE_DIR}/include)

# 출력 설정
set_target_properties(detective_core PROPERTIES
    OUTPUT_NAME "detective_core"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# ═══════════════════════════════════════════════
# 플랫폼별 설정
# ═══════════════════════════════════════════════
if(WIN32)
    target_compile_definitions(detective_core PRIVATE _WIN32)
    target_compile_definitions(blake3_internal PRIVATE _WIN32)
endif()

# ═══════════════════════════════════════════════
# 레거시 blake3 DLL (기존 호환용)
# ═══════════════════════════════════════════════
set(BLAKE3_LEGACY_SOURCES
    src/internal/blake3.c
    src/hash.c
)

add_library(blake3 SHARED ${BLAKE3_LEGACY_SOURCES})
set_target_properties(blake3 PROPERTIES
    OUTPUT_NAME "blake3"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if(WIN32)
    target_compile_definitions(blake3 PRIVATE _WIN32)
endif()

target_include_directories(blake3 PUBLIC ${PROJECT_SOURCE_DIR}/include)