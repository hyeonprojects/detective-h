cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# LLVM 설정
set(LLVM_DIR "C:/Program Files/LLVM/lib/cmake/llvm")
find_package(LLVM REQUIRED CONFIG)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SOURCE_FILES
    src/main.c
    src/internal/internal.c
)

# 플랫폼별 설정
if(WIN32)
    set(LIBRARY_EXTENSION ".dll")
elseif(APPLE)
    set(LIBRARY_EXTENSION ".dylib")
else()
    set(LIBRARY_EXTENSION ".so")
endif()