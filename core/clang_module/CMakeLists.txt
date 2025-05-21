cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# LLVM 설정
set(LLVM_DIR "C:/Program Files/LLVM/lib/cmake/llvm")
find_package(LLVM REQUIRED CONFIG)

include_directories(${PROJECT_SOURCE_DIR}/include)

# 기존 소스 파일
set(SOURCE_FILES
    src/main.c
    src/internal/internal.c
)

# Blake2b 라이브러리 소스 파일
set(BLAKE2B_SOURCE_FILES
    src/internal/blake2b.c
)

# 플랫폼별 설정
if(WIN32)
    set(LIBRARY_EXTENSION ".dll")
elseif(APPLE)
    set(LIBRARY_EXTENSION ".dylib")
else()
    set(LIBRARY_EXTENSION ".so")
endif()

# Blake2b 공유 라이브러리 빌드
add_library(blake2b SHARED ${BLAKE2B_SOURCE_FILES})
set_target_properties(blake2b PROPERTIES 
    OUTPUT_NAME "blake2b"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# 헤더 파일 경로 추가
target_include_directories(blake2b PUBLIC ${PROJECT_SOURCE_DIR}/include)