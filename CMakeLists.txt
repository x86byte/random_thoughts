cmake_minimum_required(VERSION 4.2)
project(random_thoughts)

set(CMAKE_CXX_STANDARD 23)

include_directories(transofrmer)
include_directories(transofrmer/PE)
include_directories(transofrmer/PE/_MAIN)
include_directories(transofrmer/PE/Instrumentation)
include_directories(transofrmer/PE/Instrumentation/materialization)
include_directories(transofrmer/PE/Instrumentation/materialization/state)

add_executable(random_thoughts
        transofrmer/PE/_MAIN/main.cpp
        transofrmer/PE/Instrumentation/materialization/state/pe.hpp)
