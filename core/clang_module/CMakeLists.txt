cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-fexec-charset=CP949")
set(CMAKE_CXX_FLAGS "-fexec-charset=CP949")

# Set locale to UTF-8
set(ENV{LC_ALL} "en_US.UTF-8")
set(ENV{LANG} "en_US.UTF-8")

add_library(core_lib SHARED src/hash.c)

target_include_directories(core_lib PUBLIC include)

set_target_properties(core_lib PROPERTIES
        VERSION 0.1.0
        PREFIX ""
        SUFFIX ".so"
        OUTPUT_NAME "core")