cmake_minimum_required(VERSION 3.31)

project(random_thoughts)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(RAWPDB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    raw_pdb
    GIT_REPOSITORY https://github.com/MolecularMatters/raw_pdb.git
    GIT_TAG 43cc59b
)

FetchContent_MakeAvailable(raw_pdb)

add_executable(random_thoughts
    transofrmer/PE/_MAIN/main.cpp
    transofrmer/PDB/PdbReader.cpp
    transofrmer/PE/Instrumentation/materialization/state/PE.cpp
)

target_include_directories(random_thoughts PRIVATE
    transofrmer
    transofrmer/PE
    transofrmer/PE/_MAIN
    transofrmer/PE/Instrumentation
    transofrmer/PE/Instrumentation/materialization
    transofrmer/PE/Instrumentation/materialization/state
)

target_link_libraries(random_thoughts PRIVATE
    raw_pdb
)