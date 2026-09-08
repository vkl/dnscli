# Specify the minimum version of CMake that can run this script
cmake_minimum_required(VERSION 3.12)

# Project name and version
project(dnscli VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(_DEFAULT_SOURCE _XOPEN_SOURCE=700)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

#add_compile_definitions(DEBUG_TRACE)

set(CMAKE_C_FLAGS_DEBUG
    "${CMAKE_C_FLAGS_DEBUG} -O0 -g3 -fno-omit-frame-pointer"
)

set(CMAKE_C_FLAGS_RELEASE
    "${CMAKE_C_FLAGS_RELEASE} -O2"
)

set(CMAKE_C_FLAGS_RELWITHDEBINFO
    "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O2 -g3 -fno-omit-frame-pointer"
)

add_subdirectory(lib)
add_executable(dnscli
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

find_package(Threads REQUIRED)
target_link_libraries(dnscli PRIVATE Threads::Threads dns)

set_target_properties(dnscli
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/$<CONFIG>")

