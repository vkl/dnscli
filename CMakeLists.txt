# Specify the minimum version of CMake that can run this script
cmake_minimum_required(VERSION 3.12)

# Project name and version
project(dnscli VERSION 1.0)

# Request C++ 11 standard features
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
add_subdirectory(lib)

# Compile the passed source files into an executable 
add_executable(dnscli 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
target_link_libraries(dnscli dns)
# Set the output directory for executables
set_target_properties(dnscli
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/$<CONFIG>")
