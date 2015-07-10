cmake_minimum_required(VERSION 2.8)

set(modeler_SRCS
    modeler.cc
)

add_library(modeler STATIC ${modeler_SRCS})

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g")

