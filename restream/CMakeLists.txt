#cmake_minimum_required(VERSION 2.8)

set(restream_SRCS
    restream.cc
    restream_ssn.cc
    ssn.cc
)

add_library(restream STATIC ${restream_SRCS})

add_definitions(-fPIC)

target_link_libraries(restream crypt util pthread rt nsl resolv m c dl dnet)

include_directories(../decoder ../logger)

set(CMAKE_CXX_FLAGS "-g")

