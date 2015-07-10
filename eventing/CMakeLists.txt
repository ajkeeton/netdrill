cmake_minimum_required(VERSION 2.8)

set(eventing_SRCS
    eventing.cc
    actions.cc
)

add_library(eventing STATIC ${eventing_SRCS})

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g")

include_directories(
    ../decoder
    ../logger
)
