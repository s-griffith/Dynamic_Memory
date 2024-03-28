cmake_minimum_required(VERSION 3.22)
project(ex2)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
add_executable(ex2
        malloc_1.cpp
        malloc_2.cpp
        malloc_3.cpp
        malloc_4.cpp
        )
set_target_properties(ex2 PROPERTIES LINKER_LANGUAGE CXX)