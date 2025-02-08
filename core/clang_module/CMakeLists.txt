cmake_minimum_required(VERSION 3.30)
project(clang_module C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(clang_module src/hash.c)

target_link_libraries(clang_module
    PRIVATE my_library
)

add_library(my_library SHARED
        src/hash.c
)

# Windows에서는 .dll, Linux에서는 .so가 생성됨
if(WIN32)
    set_target_properties(my_library PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
else()
    set_target_properties(my_library PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
endif()