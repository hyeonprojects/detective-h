cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Blake2b 라이브러리 소스 파일
set(BLAKE2B_SOURCE_FILES
    src/internal/blake2b.c
    src/hash.c
)

# Blake2b 공유 라이브러리 빌드
add_library(blake2b SHARED ${BLAKE2B_SOURCE_FILES})

# 플랫폼별 출력 설정
set_target_properties(blake2b PROPERTIES 
    OUTPUT_NAME "blake2b"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Windows에서 DLL export 설정
if(WIN32)
    target_compile_definitions(blake2b PRIVATE _WIN32)
endif()

# 헤더 파일 경로 추가
target_include_directories(blake2b PUBLIC ${PROJECT_SOURCE_DIR}/include)