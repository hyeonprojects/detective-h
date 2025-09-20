cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Blake3 라이브러리 소스 파일
set(BLAKE3_SOURCE_FILES
    src/internal/blake3.c
    src/hash.c
)

# Blake3 공유 라이브러리 빌드
add_library(blake3 SHARED ${BLAKE3_SOURCE_FILES})

# 플랫폼별 출력 설정
set_target_properties(blake3 PROPERTIES 
    OUTPUT_NAME "blake3"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Windows에서 DLL export 설정
if(WIN32)
    target_compile_definitions(blake3 PRIVATE _WIN32)
endif()

# 헤더 파일 경로 추가
target_include_directories(blake3 PUBLIC ${PROJECT_SOURCE_DIR}/include)