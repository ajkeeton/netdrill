cmake_minimum_required(VERSION 2.8)

set(stats_SRCS
    stats.cc
)

add_library(stats STATIC ${stats_SRCS})

target_link_libraries(stats decoder)

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g")

include_directories(
    ../decoder
    ../logger
)
